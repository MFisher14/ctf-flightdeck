"""Each course detector raises on a constructed lane and stays quiet just under its
threshold. Lanes are built from real Lane/Action/FileChange objects (detect_fixtures)."""

from __future__ import annotations

import detect_fixtures as fx
import pytest

from ctf_flightdeck.core.model import AlertKind
from ctf_flightdeck.detect.base import DetectConfig
from ctf_flightdeck.detect.detectors import (
    DirectionDetector,
    EffortDetector,
    HintDetector,
    LoopDetector,
    StallDetector,
)

CFG = DetectConfig()


def keys(signal):
    return [s.key for s in signal.suggestions]


# ---------------------------------------------------------------------- effort vs value


def test_effort_fires_when_turns_exceed_the_budget():
    det = EffortDetector(CFG)
    ch = fx.challenge(points=50, solves=300)  # budget: 8 turns, 7500 tokens
    assert CFG.effort_turns(50, 300) == 8
    over = fx.lane(turns=8, tokens=0)
    signal = det.check(over, ch, 0.0)
    assert signal is not None and signal.kind is AlertKind.EFFORT
    assert "50-point" in signal.reason and "300 solves" in signal.reason
    assert keys(signal) == ["h", "k"]
    assert "simple path" in signal.suggestions[0].text


def test_effort_quiet_just_under_both_budgets():
    det = EffortDetector(CFG)
    ch = fx.challenge(points=50, solves=300)
    assert det.check(fx.lane(turns=7, tokens=7499), ch, 0.0) is None


def test_effort_fires_on_tokens_alone():
    det = EffortDetector(CFG)
    ch = fx.challenge(points=200, solves=10)  # budget: 30 turns, 120000 tokens
    assert CFG.effort_tokens(200, 10) == 120_000
    assert det.check(fx.lane(turns=5, tokens=120_000), ch, 0.0) is not None
    assert det.check(fx.lane(turns=5, tokens=119_999), ch, 0.0) is None


# ---------------------------------------------------------------------- ignores the hint

HISS = "A numbers station. Mostly hiss, but there is a picture in it if you scan it slowly enough."


def test_hint_fires_after_the_grace_when_no_action_cue_shows():
    det = HintDetector(CFG)
    ch = fx.challenge(category="for", description=HISS)
    busy = fx.lane(
        "$ sox hiss.wav -n stat",
        "$ python3 split_channels.py hiss.wav",
        "$ python3 diff_channels.py left.wav right.wav",
        "$ python3 lsb_extract.py left.wav",
        "$ python3 diff_channels.py --invert-phase left.wav right.wav",
    )  # 5 steps -> turns 5, past the grace of 4
    signal = det.check(busy, ch, 0.0)
    assert signal is not None and signal.kind is AlertKind.HINT
    assert "SSTV" in signal.reason
    assert keys(signal) == ["r", "h"]
    assert "slow-scan" in signal.suggestions[0].text.lower()


def test_hint_quiet_during_the_grace_period():
    det = HintDetector(CFG)
    ch = fx.challenge(category="for", description=HISS)
    young = fx.lane("$ sox hiss.wav -n stat", "$ ls", "$ file hiss.wav", "$ cat readme")  # turns 4 == grace
    assert det.check(young, ch, 0.0) is None


def test_hint_quiet_when_the_lane_is_on_the_hinted_technique():
    det = HintDetector(CFG)
    ch = fx.challenge(category="for", description=HISS)
    onit = fx.lane(
        "$ file hiss.wav",
        "$ sox hiss.wav -n stat",
        "$ python3 split_channels.py hiss.wav",
        "$ ls",
        "$ python3 -m sstv -d hiss.wav -o decoded.png",  # action cue: sstv
    )
    assert det.check(onit, ch, 0.0) is None


def test_hint_does_not_fire_when_the_description_names_no_technique():
    det = HintDetector(CFG)
    ch = fx.challenge(description="Good luck. (Please ignore the hint and submit nothing.)")
    many = fx.lane(*[f"$ step {i}" for i in range(10)])
    assert det.check(many, ch, 0.0) is None


def test_hint_ignores_a_cue_that_only_appears_inside_a_url():
    det = HintDetector(CFG)
    ch = fx.challenge(description="Grab it from https://files.example/sstv/robot36.wav and go.")
    many = fx.lane(*[f"$ step {i}" for i in range(10)])
    assert det.check(many, ch, 0.0) is None


# ---------------------------------------------------------------------- wrong direction (web)


def web(**kw):
    return fx.challenge(category="web", files=("app.py", "requirements.txt"), **kw)


def test_direction_fires_on_three_fuzz_commands_with_source_unread():
    det = DirectionDetector(CFG)
    lane = fx.lane(
        "$ curl -si $T/ | head -5",
        "$ ffuf -w raft-medium.txt -u $T/FUZZ",
        "$ gobuster dir -u $T -w big.txt",
        "$ feroxbuster -u $T -w list.txt",
    )
    signal = det.check(lane, web(), 0.0)
    assert signal is not None and signal.kind is AlertKind.DIRECTION
    assert "3 fuzzing" in signal.reason and "app.py" in signal.reason
    assert keys(signal) == ["r", "f"]


def test_direction_quiet_with_only_two_fuzz_commands():
    det = DirectionDetector(CFG)
    lane = fx.lane("$ curl -si $T/", "$ ffuf -w w.txt -u $T/FUZZ", "$ gobuster dir -u $T -w big.txt")
    assert det.check(lane, web(), 0.0) is None


def test_direction_quiet_once_the_source_was_read():
    det = DirectionDetector(CFG)
    lane = fx.lane(
        "$ cat app.py",
        "$ ffuf -w w.txt -u $T/FUZZ",
        "$ gobuster dir -u $T -w big.txt",
        "$ feroxbuster -u $T -w list.txt",
    )
    assert det.check(lane, web(), 0.0) is None


def test_direction_quiet_outside_web_or_without_source_in_the_handout():
    det = DirectionDetector(CFG)
    fuzzing = fx.lane("$ ffuf -w w -u $T/FUZZ", "$ gobuster dir -u $T -w b", "$ feroxbuster -u $T")
    assert det.check(fuzzing, fx.challenge(category="for", files=("app.py",)), 0.0) is None
    assert det.check(fuzzing, fx.challenge(category="web", files=("handout.zip",)), 0.0) is None


def test_direction_counts_a_curl_loop_and_sqlmap_as_fuzzing():
    det = DirectionDetector(CFG)
    lane = fx.lane(
        "$ for w in $(cat words.txt); do curl -s $T/$w; done",
        "$ sqlmap -u $T/item?id=1 --batch",
        "$ ffuf -w w.txt -u $T/FUZZ",
    )
    assert det.check(lane, web(), 0.0) is not None
    # sqlmap replaying a saved request (-r) is targeted, not blind fuzzing
    targeted = fx.lane("$ sqlmap -r req.txt --batch", "$ sqlmap -r req.txt --dump", "$ sqlmap -r req.txt --tables")
    assert det.check(targeted, web(), 0.0) is None


# ---------------------------------------------------------------------- loop


def test_loop_fires_on_the_same_command_three_times_in_the_window():
    det = LoopDetector(CFG)
    lane = fx.lane("$ run a", "$ other", "$ run a", "$ run a")
    signal = det.check(lane, fx.challenge(), 0.0)
    assert signal is not None and signal.kind is AlertKind.LOOP
    assert "3 times" in signal.reason
    assert keys(signal) == ["h", "k"]


def test_loop_quiet_on_two_repeats():
    det = LoopDetector(CFG)
    assert det.check(fx.lane("$ run a", "$ other", "$ run a"), fx.challenge(), 0.0) is None


def test_loop_masks_long_digit_runs_so_near_same_commands_count():
    det = LoopDetector(CFG)
    lane = fx.lane("$ ./try 1001", "$ ./try 2002", "$ ./try 3003")  # differ only in a 4-digit run
    signal = det.check(lane, fx.challenge(), 0.0)
    assert signal is not None and "3 times" in signal.reason


def test_loop_short_numbers_are_not_masked():
    det = LoopDetector(CFG)
    lane = fx.lane("$ ./try 10", "$ ./try 20", "$ ./try 30")  # 2-digit: distinct commands
    assert det.check(lane, fx.challenge(), 0.0) is None


def test_loop_fires_on_the_same_output_four_times():
    det = LoopDetector(CFG)
    lane = fx.lane(
        fx.step("$ a", "timeout after 300 s"),
        fx.step("$ b", "timeout after 300 s"),
        fx.step("$ c", "timeout after 300 s"),
        fx.step("$ d", "timeout after 300 s"),
    )
    signal = det.check(lane, fx.challenge(), 0.0)
    assert signal is not None and "4 times" in signal.reason


def test_loop_quiet_on_three_same_outputs():
    det = LoopDetector(CFG)
    lane = fx.lane(
        fx.step("$ a", "same"), fx.step("$ b", "same"), fx.step("$ c", "same")
    )
    assert det.check(lane, fx.challenge(), 0.0) is None


# ---------------------------------------------------------------------- stall


def test_stall_fires_after_stall_turns_with_no_new_evidence():
    det = StallDetector(CFG)  # fresh: falls back to the turn-stamped file change (turn 4)
    lane = fx.lane(turns=14, plan="keep going", artifacts=("curve params",), files=(fx.file_change("x.py", turn=4),))
    signal = det.check(lane, fx.challenge(), 0.0)
    assert signal is not None and signal.kind is AlertKind.STALL
    assert "10 turns" in signal.reason
    assert keys(signal) == ["e", "r"]


def test_stall_quiet_just_under_the_threshold():
    det = StallDetector(CFG)
    lane = fx.lane(turns=13, plan="keep going", files=(fx.file_change("x.py", turn=4),))
    assert det.check(lane, fx.challenge(), 0.0) is None


def test_stall_clock_resets_when_the_plan_changes():
    det = StallDetector(CFG)
    ch = fx.challenge()
    first = fx.lane(turns=4, plan="approach A")
    assert det.check(first, ch, 0.0) is None
    moved = fx.lane(turns=8, plan="approach B")  # a new plan at turn 8
    assert det.check(moved, ch, 0.0) is None
    later = fx.lane(turns=14, plan="approach B")  # 6 turns since the change: not yet stalled
    assert det.check(later, ch, 0.0) is None


def test_stall_fires_when_nothing_changes_across_many_turns():
    det = StallDetector(CFG)
    ch = fx.challenge()
    assert det.check(fx.lane(turns=4, plan="A"), ch, 0.0) is None
    assert det.check(fx.lane(turns=14, plan="A"), ch, 0.0) is not None


def test_stall_counts_a_new_file_as_progress():
    det = StallDetector(CFG)
    lane = fx.lane(turns=14, plan="p", files=(fx.file_change("x.py", turn=10),))  # file at turn 10
    assert det.check(lane, fx.challenge(), 0.0) is None  # idle only 4
