"""What a run under autopilot leaves for the commands after it: the post-flight report's
Autopilot section, the flight card and the scorecard, none of which count an intervention
autopilot made by rule as the player's. Runs are scripted on a real deck, event log and
transcript log (test_postflight.py's Script)."""

from __future__ import annotations

from pathlib import Path

from ctf_flightdeck.autopilot import Autopilot, Budget
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.postflight import analyse, report, summary
from ctf_flightdeck.practice_mode import score
from ctf_flightdeck.share import APPROVE_ONLY, HANDS_OFF, HANDS_ON, card, mode, steering, verdicts

from test_postflight import FLAGS, Script, write_board
from test_share import SETUP, lines


def flown(folder: Path, *, player: tuple[str, ...] = (), budget: Budget = Budget(tokens=6000)):
    """A run autopilot flew: it kills a looping lane (alpha), escalates a stalled one (bravo),
    which then solves with the player's approval when `player` has "approve", and disengages
    at its token budget. `player` may also have "hint": the player's own steering."""
    folder.mkdir(exist_ok=True)
    board = load_board(write_board(folder / "board"))
    run = Script(folder / "run", flags=FLAGS, max_lanes=2)
    pilot = Autopilot(run.deck, budget)
    pilot.attach()
    assert pilot.engage().ok
    run.release([b.challenge for b in board.challenges], ["alpha", "bravo"])
    alpha, bravo = run.lane("alpha"), run.lane("bravo")
    run.at(10)
    run.turn(alpha, "ls")
    run.deck.report(alpha, TurnReport(turn=False, alerts=(Alert(AlertKind.LOOP, "the same command three times"),)))
    pilot.step()
    run.at(20)
    run.turn(bravo, "curl /")
    run.deck.report(bravo, TurnReport(turn=False, alerts=(Alert(AlertKind.STALL, "no new step for a while"),)))
    pilot.step()
    if "hint" in player:
        run.at(25)
        run.do(iv.Hint(bravo, "look at the cookie"))
    run.at(30)
    run.turn(bravo, "curl -b admin=1 /", flag="t{bravo}")
    if "approve" in player:
        run.do(iv.Approve(bravo))
    pilot.step()  # no lane runs now (bravo solved, or waits for the player): alpha goes round again on the next model
    run.at(40)
    run.turn(run.newest(), "strings blob", tokens=4000)  # alpha, round two, takes the run to its budget
    pilot.step()
    return run, pilot, board


def test_the_report_has_an_autopilot_section_and_counts_none_of_its_interventions_as_yours(tmp_path):
    run, pilot, _ = flown(tmp_path)
    text = report(run.close())
    assert "## Interventions\n\nNo interventions in this run.\n" in text  # the player did nothing
    section = text.split("## Autopilot\n", 1)[1].split("\n## ", 1)[0]
    assert "Autopilot made 5 interventions by rule (0 refused) and disengaged 1 time. They are not counted among your interventions above." in section
    assert "· autopilot engaged: run budget 6k tokens" in section
    assert "· disengaged: the run budget is reached: 7k of 6k tokens spent" in section
    assert "### Interventions by rule (5)" in section
    for line in ("autopilot: kill L01 (park) → Killed L01; Alpha is parked",
                 "autopilot: escalate L02 → Escalated L02 from small to big",
                 "autopilot: queue Alpha on big → Started L03 on Alpha on big",
                 "autopilot: pause L02 → Paused L02",  # it waits for you with its flag: paused at the budget, flag kept
                 "autopilot: pause L03 → Paused L03"):
        assert line in section, line
    assert "you: " not in section
    timeline = text.split("## Timeline\n", 1)[1].split("\n## ", 1)[0]
    assert "autopilot: kill L01 (park)" in timeline and "you: kill" not in timeline
    assert "Autopilot: 5 interventions by rule, disengaged 1 time" in summary(run.close())


def test_the_players_own_interventions_are_still_theirs_beside_autopilots(tmp_path):
    run, _, _ = flown(tmp_path, player=("hint", "approve"))
    text = report(run.close())
    mine = text.split("## Interventions\n", 1)[1].split("\n## ", 1)[0]
    assert mine.startswith("\n2 interventions, 0 refused.")
    assert "you: hint L02: look at the cookie" in mine and "autopilot" not in mine
    assert "Autopilot made 4 interventions by rule" in text  # bravo solved, so its lane was not there to pause


def test_taking_the_controls_back_and_what_the_guardrails_kept_are_in_the_section(tmp_path):
    run, pilot, _ = flown(tmp_path, budget=Budget(tokens=1_000_000))
    run.deck.report(run.newest(), TurnReport(turn=False, action="big declined", gave_up="the model declined", declined=True))
    pilot.step()
    pilot.off()
    section = report(run.close()).split("## Autopilot\n", 1)[1].split("\n## ", 1)[0]
    assert "disengaged 0 times" in section
    assert "· off, the controls back with you: you switched it off" in section
    assert "### Kept for you (1)" in section
    assert "big declined Alpha (L03): autopilot sends no refused request on to another model" in section


def test_a_run_without_autopilot_has_no_autopilot_section_or_card_line(tmp_path):
    board = load_board(write_board(tmp_path / "board"))
    run = Script(tmp_path / "run", flags=FLAGS)
    run.release([b.challenge for b in board.challenges], ["alpha"])
    run.at(5)
    run.turn(run.lane("alpha"), "ls")
    run.do(iv.Kill(run.lane("alpha"), requeue=False))
    record = run.close()
    assert "Autopilot" not in report(record) and "Autopilot" not in summary(record)
    assert "autopilot" not in card(record, SETUP)
    assert steering(analyse(record)) == {"kill": 1}


def test_the_flight_card_counts_only_the_players_steps_and_says_what_autopilot_did(tmp_path):
    run, _, _ = flown(tmp_path)
    record = run.close()
    flight = analyse(record)
    assert not steering(flight) and not verdicts(flight) and mode(flight) == HANDS_OFF
    shown = lines(card(record, SETUP))
    assert shown["you steered"] == "nothing" and shown["you approved or declined"] == "nothing"
    assert shown["autopilot"] == "engaged, 5 interventions by rule"
    assert shown["mode"].startswith(HANDS_OFF)


def test_the_card_mode_follows_what_the_player_did_under_autopilot(tmp_path):
    approved, _, _ = flown(tmp_path / "a", player=("approve",))
    record = approved.close()
    assert mode(analyse(record)) == APPROVE_ONLY and verdicts(analyse(record)) == {"approve": 1}
    assert lines(card(record, SETUP))["autopilot"] == "engaged, 4 interventions by rule"
    steered, _, _ = flown(tmp_path / "b", player=("hint", "approve"))
    record = steered.close()
    assert mode(analyse(record)) == HANDS_ON and steering(analyse(record)) == {"hint": 1}


def test_the_scorecard_counts_the_players_interventions_only(tmp_path):
    untouched, _, board = flown(tmp_path / "a")
    untouched.close()
    assert score(untouched.log.path, board).interventions == 0
    helped, _, board = flown(tmp_path / "b", player=("hint", "approve"))
    helped.close()
    assert score(helped.log.path, board).interventions == 2


def test_a_writeup_draft_lists_autopilots_steps_apart_from_yours(tmp_path):
    from ctf_flightdeck import writeup

    run, _, _ = flown(tmp_path, player=("approve",))  # bravo: escalated by autopilot, solved with your approval
    text = writeup.draft(run.close(), "bravo")
    section = text.split("## Your interventions\n", 1)[1].split("\n## ", 1)[0]
    assert "- Turn 2, approval: `submit t{bravo}`" in section
    assert "Autopilot stepped in, by rule:\n\n- Turn 1, `escalated small → big with a summary`" in section
    assert "the lane worked on its own" not in section
    yours = section.split("Autopilot stepped in, by rule:")[0]
    assert "escalat" not in yours
