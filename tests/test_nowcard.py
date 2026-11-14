"""The "needs you now" card of the focus view: the calm one (details off) and the full one.

The pure tests read what views.calm_card and views.now_card make of a lane; the app tests read
the card as a player sees it, from the screen. Every lane here is synthetic: its commands and
outputs are written in this file and nothing is run.
"""

from __future__ import annotations

import io

import pytest
import rich.console
from textual.widgets import Static

from ctf_flightdeck.console import theme, views
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.focus import DETAILS_OFF, DETAILS_ON
from ctf_flightdeck.console.screens import KillPrompt
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Alert, AlertKind, Challenge, DeckConfig, Lane, LaneState, Pending, PendingKind
from ctf_flightdeck.detect import DetectConfig, LoopDetector, Watch
from ctf_flightdeck.detect.base import suggestions
from ctf_flightdeck.detect.detectors import default_detectors
from ctf_flightdeck.text import untrusted
from test_console import PHONE, color_of, drive, footer_line, open_focus, osc, press, quiet_deck, region_text, screen_lines, send, status_line
from test_console import shown as shown_osc

BIG = (254, 71)  # the terminal of the report this card answers
NARROW = (120, 36)  # where the full card was cut, and the approval's rows with it
HEREDOC = "cd /work && python3 - <<'PY'\nfrom Crypto.Util.number import long_to_bytes\nn = 0x1234\nprint(long_to_bytes(pow(c, d, n)))\nPY"
TRACEBACK = "Traceback (most recent call last):\n  File \"<stdin>\", line 4\nNameError: name 'c' is not defined"
ASKS = "◆ waiting for you: raise the cap by 50% (now 424k of 400k tokens)"
FOUR_CALM = [  # the calm card of four_at_once, whole
    ASKS,
    "  1 more budget   0 stop the lane",
    "  also: looping · past its effort budget · stalled   ctrl+o shows all",
]


def four_at_once(layout: str = "simple") -> tuple[Deck, FlightdeckApp, Lane]:
    """The lane of the report: twelve turns of one failing command on a 0-point challenge,
    watched by the real detectors. It is over its token cap and waits for more budget, and
    its Budget, Loop, Effort vs value and Stall alerts are all open."""
    deck = quiet_deck(DeckConfig(event="practice", models=("glm", "big")))
    Watch(deck, default_detectors(DetectConfig())).attach()
    deck.release([Challenge("c", "Baby RSA", "cry", 0, solves=0, description="n, e, c are in out.txt")], [QueueEntry("c", "glm", token_cap=400_000)])
    (lane,) = deck.lanes_on("c")
    for _ in range(12):
        deck.clock.advance(20)
        deck.report(lane.id, TurnReport(action=f"$ {HEREDOC}", output=TRACEBACK, tokens=35_300))
    assert {alert.kind for alert in lane.alerts} == {AlertKind.BUDGET, AlertKind.LOOP, AlertKind.EFFORT, AlertKind.STALL}
    assert lane.pending is not None and lane.pending.kind is PendingKind.BUDGET and lane.state is LaneState.WAITING
    return deck, FlightdeckApp(deck, refresh_seconds=None, layout=layout), lane


def one_lane(layout: str = "simple", *, watch: bool = False) -> tuple[Deck, FlightdeckApp, Lane]:
    """A console in `layout` with one lane, L01, that has done nothing yet. `watch`: the real
    loop detector reads its turns."""
    deck = quiet_deck(DeckConfig(event="ev", models=("glm",), max_lanes=4))
    if watch:
        Watch(deck, [LoopDetector(DetectConfig())]).attach()
    deck.release([Challenge("crackme", "Crack Me Maybe", "rev", 300)], [QueueEntry("crackme", "glm")])
    return deck, FlightdeckApp(deck, refresh_seconds=None, layout=layout), deck.lanes["L01"]


def alert(kind: AlertKind, reason: str = "", *answers: tuple[str, ...]) -> Alert:
    return Alert(kind, reason or f"why {kind.value} fired", suggestions(*answers))


def raise_alerts(deck: Deck, *alerts: Alert) -> None:
    deck.report("L01", TurnReport(turn=False, alerts=alerts))


LOOP = ("The same command ran 4 times in the last 4 turns: python3 solve.py.", ("h", "Hint", "You are repeating python3 solve.py."),
        ("k", "Kill and re-queue fresh"))
STALL = ("No new file, artifact, plan or candidate flag for 11 turns.", ("e", "Escalate to a stronger model with a summary"),
         ("r", "Redirect with a new approach"))


def calm(deck: Deck, lane: Lane) -> list[str]:
    """The calm card's rows."""
    return views.calm_card(deck, lane).plain.split("\n")


def full(deck: Deck, lane: Lane, **how: bool) -> list[str]:
    """The full card's rows as a terminal too wide to wrap any of them draws it, without its border."""
    console = rich.console.Console(width=2000, record=True, color_system=None, file=io.StringIO())
    console.print(views.now_card(deck, lane, **how))
    return [row.strip("│ ").rstrip() for row in console.export_text().splitlines()[1:-1]]


def card(app: FlightdeckApp) -> list[str]:
    """The card as it is drawn: every row of its box on the screen, the border with it, without
    the box's scroll bar (the columns the card itself has)."""
    box, now = app.screen.query_one("#now-scroll").region, app.screen.query_one("#now").region
    return [row[now.x:now.right].rstrip() for row in screen_lines(app)[box.y:box.bottom]]


def inside(app: FlightdeckApp) -> list[str]:
    """The rows inside the drawn card's border, without it."""
    return [row.strip("│").rstrip()[1:] for row in card(app)[1:-1]]


def one_line(rows: list[str]) -> str:
    """Rows as one line, their side borders and the breaks between them left out: what a wrapped card says."""
    return " ".join(" ".join(rows).replace("│", " ").split())


# ---------------------------------------------------------------------- the calm card's rows


def test_four_things_at_once_are_three_rows_the_question_its_answers_and_what_else_is_open():
    deck, _, lane = four_at_once()
    assert calm(deck, lane) == FOUR_CALM
    assert views.now_card(deck, lane, simple=True, calm=True).plain == "\n".join(FOUR_CALM)
    assert [(answer.number, answer.key) for answer in views.quick_answers(lane)] == [("1", "a"), ("0", "d")]  # what row 2's numbers do


def test_an_alert_alone_is_the_question_with_its_reason_and_numbered_answers_and_no_third_row():
    deck, _, lane = one_lane()
    raise_alerts(deck, alert(AlertKind.LOOP, *LOOP))
    assert calm(deck, lane) == [
        "▲ Loop: The same command ran 4 times in the last 4 turns: python3 solve.py.",
        '  1 hint "You are repeating python3 solve.py."   2 kill and re-queue fresh   /dismiss not a problem',
    ]


def test_the_most_urgent_alert_is_the_question_and_the_others_are_named_in_the_order_of_their_urgency():
    deck, _, lane = one_lane()
    raise_alerts(deck, alert(AlertKind.STALL, *STALL), alert(AlertKind.DIRECTION), alert(AlertKind.HINT), alert(AlertKind.LOOP, *LOOP),
                 alert(AlertKind.TEAMMATE), alert(AlertKind.EFFORT))
    rows = calm(deck, lane)
    assert rows[0].startswith("▲ Loop: The same command ran 4 times") and rows[1].startswith('  1 hint "You are repeating')
    assert rows[2] == "  also: past its effort budget · ignores the hint · wrong direction · stalled · teammate   ctrl+o shows all"


def test_an_approval_is_the_question_over_any_alert_and_the_alert_it_is_about_is_not_named_beside_it():
    deck, _, lane = one_lane()
    lane.token_cap = 10_000
    deck.report("L01", TurnReport(action="ls", tokens=8_500))  # past 80% of its cap: the alert, no approval yet
    assert [a.kind for a in lane.alerts] == [AlertKind.BUDGET] and lane.pending is None
    rows = calm(deck, lane)
    assert rows[0].startswith("▲ Budget: At 85% of its cap") and len(rows) == 2  # the alert is the question
    raise_alerts(deck, alert(AlertKind.STALL, *STALL))
    assert calm(deck, lane)[2] == "  also: stalled   ctrl+o shows all"
    deck.report("L01", TurnReport(action="ls", tokens=2_000))  # past the cap: it waits for more
    assert lane.pending is not None and lane.pending.kind is PendingKind.BUDGET and lane.alert(AlertKind.BUDGET) is not None
    assert calm(deck, lane) == [
        "◆ waiting for you: raise the cap by 50% (now 10k of 10k tokens)",
        "  1 more budget   0 stop the lane",
        "  also: stalled   ctrl+o shows all",  # "near its cap" is what the approval asks about
    ]


def test_a_live_box_approval_names_a_budget_alert_beside_it():
    deck, _, lane = one_lane()
    lane.token_cap = 10_000
    deck.report("L01", TurnReport(action="ls", tokens=8_500, pending=Pending(PendingKind.LIVE_BOX, "connect to the live instance")))
    assert calm(deck, lane) == [
        "◆ waiting for you: connect to the live instance",
        "  1 use the live box   0 stay off it",
        "  also: near its cap   ctrl+o shows all",
    ]


def test_further_approvals_and_messages_not_read_yet_are_counted_on_the_third_row():
    deck, app, lane = one_lane()
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, "connect to the live instance")))
    assert len(calm(deck, lane)) == 2  # nothing else is open
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, "scan its other port")))
    assert len(lane.waiting) == 1 and calm(deck, lane)[2] == "  also: 1 more approval after this one   ctrl+o shows all"
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, "log in over ssh")))
    assert calm(deck, lane)[2] == "  also: 2 more approvals after this one   ctrl+o shows all"
    assert deck.apply(iv.Hint("L01", "try the header")).ok
    assert calm(deck, lane)[2] == "  also: 2 more approvals after this one · 1 message it has not read yet   ctrl+o shows all"
    assert deck.apply(iv.Hint("L01", "then the footer")).ok
    raise_alerts(deck, alert(AlertKind.LOOP, *LOOP))
    assert calm(deck, lane) == [
        "◆ waiting for you: connect to the live instance",
        "  1 use the live box   0 stay off it",
        "  also: looping · 2 more approvals after this one · 2 messages it has not read yet   ctrl+o shows all",
    ]


def test_a_flag_approval_answers_in_the_approvals_words_and_shows_the_flag_once():
    deck, _, lane = one_lane()
    deck.report("L01", TurnReport(action="cat flag.txt", flag="flag{synthetic_one}"))
    assert lane.pending is not None and lane.pending.kind is PendingKind.SUBMIT and lane.alert(AlertKind.FLAG) is not None
    assert views.quick_answers(lane)[0].label == lane.pending.detail  # the why line's answer 1 is the detail: the card's row 1 has it
    rows = calm(deck, lane)
    assert rows == [f"◆ waiting for you: {lane.pending.detail}", "  1 submit it   0 do not submit"]  # no "a flag to check" beside it
    assert "\n".join(rows).count("flag{synthetic_one}") == 1


def test_a_hint_answer_quotes_the_first_48_characters_of_what_it_sends_without_credentials_and_drawn_literally():
    """Answer 1 of a loop sends the detector's hint at once, and the hint quotes the command the
    lane repeats: the card shows the start of it, a credential's name without its value, and an
    escape sequence or markup in it as text."""
    deck, _, lane = one_lane(watch=True)
    token = "ab12cd34" * 4
    for _ in range(3):
        deck.report("L01", TurnReport(action=f"CTFD_TOKEN={token} python3 solve.py", output="no"))
    (loop,) = lane.alerts
    assert loop.kind is AlertKind.LOOP and token in loop.suggestions[0].text  # the deck's own, as the detector quoted it
    answers = calm(deck, lane)[1]
    assert answers == '  1 hint "You are repeating CTFD_TOKEN=[redacted] python3 …"   2 kill and re-queue fresh   /dismiss not a problem'
    quoted = answers.split('"')[1]
    assert len(quoted) == views.CALM_QUOTE + 1 and quoted.endswith("…") and token not in "\n".join(calm(deck, lane))

    deck, _, lane = one_lane(watch=True)
    for _ in range(3):
        deck.report("L01", TurnReport(action=f"{osc('pwned')}[@click=app.quit]x[/]", output="no"))
    text = views.calm_card(deck, lane)
    assert f'  1 hint "You are repeating {shown_osc("pwned")}^[\\[@click=app.quit]…"   2 kill and re-queue fresh' in text.plain
    assert "\x1b" not in text.plain and not any(span.style and "click" in str(span.style) for span in text.spans)  # text, not markup


def test_an_answer_that_only_opens_a_prompt_quotes_nothing_and_more_than_three_answers_are_counted():
    deck, _, lane = one_lane()
    raise_alerts(deck, alert(AlertKind.BUDGET, "At 85% of its cap.", ("a", "Approve 50% more budget now"), ("e", "Escalate to a stronger model"),
                             ("k", "Kill the lane", "not sent: k opens its prompt"), ("p", "Pause it"), ("f", "Fork it"), ("", "Or wait")))
    assert [answer.number for answer in views.quick_answers(lane)] == ["1", "2", "3", "4", "5"]
    assert calm(deck, lane) == [
        "▲ Budget: At 85% of its cap.",
        "  1 approve 50% more budget now   2 escalate to a stronger model   3 kill the lane   +2 more",  # no /dismiss: not about its course
    ]


def test_with_no_question_the_card_is_the_message_not_read_yet_or_how_many_or_what_flightdeck_did():
    deck, app, lane = one_lane()
    assert calm(deck, lane) == [""] and views.card_border(lane) == ""  # nothing open: no card
    assert views.now_card(deck, lane, simple=True, calm=True).plain == ""
    assert views.now_card(deck, lane, calm=True).plain == "Nothing needs you on this lane. Type below to message it, or / for commands."
    assert deck.apply(iv.Hint("L01", "try the header")).ok
    assert calm(deck, lane) == ["› sent, not read yet: try the header"]
    assert deck.apply(iv.Hint("L01", "then the footer")).ok
    assert calm(deck, lane) == ["› 2 messages sent, not read yet   ctrl+o shows all"]
    raise_alerts(deck, alert(AlertKind.TEAMMATE, "the box is in use by a teammate's lane"))
    assert calm(deck, lane) == [
        "▲ Teammate solved / box in use  the box is in use by a teammate's lane",  # as the full card shows it
        "› 2 messages sent, not read yet   ctrl+o shows all",
    ]
    assert views.card_border(lane) == theme.BORDER  # nothing to answer: the plain border


def test_a_lane_that_has_ended_has_its_one_line_calm_or_not():
    deck, _, lane = one_lane()
    raise_alerts(deck, alert(AlertKind.LOOP, *LOOP))
    deck.report("L01", TurnReport(action="ls", gave_up="out of ideas"))
    assert lane.finished and views.card_border(lane) == ""
    for how in ({}, {"calm": True}):
        assert views.now_card(deck, lane, **how).plain == "gave up: out of ideas   this lane has ended; esc goes back to the fleet"
    assert views.now_card(deck, lane, simple=True, calm=True).plain == "gave up: out of ideas   this lane has ended; esc goes back to the lanes"


def test_the_cards_border_is_the_most_urgent_alerts_colour_else_the_approvals():
    deck, _, lane = one_lane()
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, "connect to the live instance")))
    assert views.card_border(lane) == theme.PURPLE
    raise_alerts(deck, alert(AlertKind.TEAMMATE))  # needs no answer: not its colour
    assert views.card_border(lane) == theme.PURPLE
    raise_alerts(deck, alert(AlertKind.STALL, *STALL))
    assert views.card_border(lane) == theme.alert_colors(AlertKind.STALL)[1] != theme.PURPLE
    raise_alerts(deck, alert(AlertKind.BUDGET))
    assert views.card_border(lane) == theme.alert_colors(AlertKind.BUDGET)[1] != theme.alert_colors(AlertKind.STALL)[1]


# ---------------------------------------------------------------------- the full card's rows


def test_the_full_card_starts_with_the_approval_and_its_two_answers_then_every_alert():
    deck, _, lane = four_at_once()
    rows = full(deck, lane)
    assert rows[:3] == [ASKS, "1  /approve   more budget", "0  /decline   stop the lane"]
    labels = [row.split("  ")[0] for row in rows if row.startswith("▲")]
    assert labels == ["▲ Budget", "▲ Loop", "▲ Effort vs value", "▲ Stall"]  # then the alerts, the most urgent first
    assert rows[-1] == "press a number to answer (chat box empty), / to pick a command, or write a message"
    compact = full(deck, lane, compact=True)
    assert compact[:3] == [ASKS, "1  /approve   more budget", "0  /decline   stop the lane"] and compact[-1] == "a number answers (chat box empty)"


def test_the_full_card_keeps_further_approvals_under_the_first_and_messages_last():
    deck, app, lane = one_lane()
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, "connect to the live instance")))
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, "scan its other port")))
    assert deck.apply(iv.Hint("L01", "try the header")).ok
    raise_alerts(deck, alert(AlertKind.LOOP, *LOOP))
    assert full(deck, lane) == [
        "◆ waiting for you: connect to the live instance",
        "1  /approve   use the live box",
        "0  /decline   stay off it",
        "then: scan its other port",
        "▲ Loop  The same command ran 4 times in the last 4 turns: python3 solve.py.",
        "/hint You are repeating python3 solve.py.   hint",  # no number: the digits answer the approval
        "/kill   kill and re-queue fresh",
        "/dismiss   not a problem: take the alert down, the lane carries on",
        "› sent, not read yet: try the header",
        "press a number to answer (chat box empty), / to pick a command, or write a message",
    ]
