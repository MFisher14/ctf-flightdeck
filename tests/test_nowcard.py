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
from ctf_flightdeck.core.model import Alert, AlertKind, Challenge, DeckConfig, FileChange, Lane, LaneState, Pending, PendingKind
from ctf_flightdeck.credentials import redact
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


TOKEN = "ab12cd34" * 4  # the value of a credential: no card shows it
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c3ludGhldGljLXNpZ25hdHVyZQ"  # synthetic
BOX = f"curl the live box with CTFD_TOKEN={TOKEN} Authorization: Bearer {JWT}"  # an approval a lane asks for, in the lane's own words
BOX_SHOWN = "curl the live box with CTFD_TOKEN=[redacted] Authorization: Bearer [redacted]"


def test_the_calm_cards_approval_shows_no_credential_as_the_transcript_shows_none_and_draws_its_detail_literally():
    """An approval's detail is the lane's own text (a live-box approval quotes what it wants to
    run). The card's question shows it as the transcript's row for the same approval does."""
    deck, _, lane = one_lane()
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, BOX)))
    assert lane.pending is not None and TOKEN in lane.pending.detail and JWT in lane.pending.detail  # the deck's own, as the lane asked
    asked = views.entry_text(deck, lane, views.entries(lane.actions)[-1]).plain
    assert asked == f"◆ asked you · turn 1: {BOX_SHOWN}"  # the transcript's row
    assert calm(deck, lane) == [f"◆ waiting for you: {BOX_SHOWN}", "  1 use the live box   0 stay off it"]
    assert views.now_card(deck, lane, simple=True, calm=True).plain.split("\n")[0] == f"◆ waiting for you: {BOX_SHOWN}"

    deck, _, lane = one_lane()
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, f"{osc('pwned')}[@click=app.quit]x[/]")))
    text = views.calm_card(deck, lane)
    assert text.plain.split("\n")[0] == f"◆ waiting for you: {shown_osc('pwned')}^[\\[@click=app.quit]x[/]"
    assert "\x1b" not in text.plain and not any(span.style and "click" in str(span.style) for span in text.spans)  # text, not markup


def test_a_credential_cut_by_the_longest_row_the_calm_card_draws_leaves_no_part_of_itself():
    deck, _, lane = one_lane()
    lead = "x" * (views.LINE_CHARS - len(" CTFD_TOKEN=[redacted]")) + " "  # the cut falls 10 characters into the value
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, f"{lead}CTFD_TOKEN={TOKEN} and more")))
    row = calm(deck, lane)[0]
    assert row == f"◆ waiting for you: {lead}CTFD_TOKEN=[redacted]" and TOKEN[:10] not in row  # cut after the value is out


def test_a_flag_shaped_like_a_credential_is_whole_on_the_card_that_asks_whether_to_submit_it():
    """What the card takes out is a credential, never the flag the run knows: the player reads
    the flag before answering 1."""
    deck, _, lane = one_lane()
    flag = "flag{" + "sk-" + "ant-" + "ab12cd34" * 5 + "}"
    deck.report("L01", TurnReport(action="cat flag.txt", flag=flag))
    assert lane.pending is not None and lane.pending.kind is PendingKind.SUBMIT
    assert redact(lane.pending.detail) != lane.pending.detail  # on its own it reads as a key
    assert calm(deck, lane) == [f"◆ waiting for you: submit {flag}", "  1 submit it   0 do not submit"]
    assert full(deck, lane)[0] == f"◆ waiting for you: submit {flag}"


def test_an_answer_that_only_opens_a_prompt_quotes_nothing_and_more_than_three_answers_are_counted():
    deck, _, lane = one_lane()
    raise_alerts(deck, alert(AlertKind.BUDGET, "At 85% of its cap.", ("a", "Approve 50% more budget now"), ("e", "Escalate to a stronger model"),
                             ("k", "Kill the lane", "not sent: k opens its prompt"), ("p", "Pause it"), ("f", "Fork it"), ("", "Or wait")))
    assert [answer.number for answer in views.quick_answers(lane)] == ["1", "2", "3", "4", "5"]
    assert calm(deck, lane) == [
        "▲ Budget: At 85% of its cap.",
        "  1 approve 50% more budget now   2 escalate to a stronger model   3 kill the lane   +2 more",  # no /dismiss: not about its course
    ]


def test_in_a_narrow_card_the_quotes_shorten_until_every_answer_fits_and_go_before_a_number_is_cut():
    """The view cuts a row at the card's edge. A row of answers that is too long would lose
    the answers after the first quote, numbers and all: the quotes give way first."""
    deck, _, lane = one_lane()
    raise_alerts(deck, alert(AlertKind.HINT, "The description hints at slow-scan TV.", ("r", "Redirect with the hinted technique", "Decode it as SSTV and read the picture"),
                             ("h", "Hint", "Think slow-scan TV, not stereo tricks")))

    def answers(width: int | None) -> str:
        return views.calm_card(deck, lane, width).plain.split("\n")[1]

    whole = '  1 redirect with the hinted technique "Decode it as SSTV and read the picture"   2 hint "Think slow-scan TV, not stereo tricks"   /dismiss not a problem'
    assert answers(None) == whole and answers(len(whole)) == whole and answers(500) == whole
    # one cell short: each quote ends a character sooner than the longer one did, and says so
    assert answers(len(whole) - 1) == ('  1 redirect with the hinted technique "Decode it as SSTV and read the pictu…"   '
                                       '2 hint "Think slow-scan TV, not stereo trick…"   /dismiss not a problem')
    least = '  1 redirect with the hinted technique "Decode it as…"   2 hint "Think slow-s…"   /dismiss not a problem'
    assert answers(len(least)) == least and views.CALM_QUOTE_MIN == 12
    bare = "  1 redirect with the hinted technique   2 hint   /dismiss not a problem"
    assert answers(len(least) - 1) == bare  # less of a quote says nothing: none
    assert answers(len(bare)) == bare and answers(20) == bare  # the rest is the edge's to cut
    assert views.now_card(deck, lane, simple=True, calm=True, width=len(least)).plain.split("\n")[1] == least
    rows = views.calm_card(deck, lane, 20).plain.split("\n")
    assert rows[0] == "▲ Ignores the hint: The description hints at slow-scan TV." and len(rows) == 2  # only the answers are fitted


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


@pytest.mark.parametrize("how", [{}, {"compact": True}], ids=["full", "compact"])
def test_the_full_cards_approval_and_the_approvals_after_it_show_no_credential(how):
    deck, _, lane = one_lane()
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, BOX)))
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, f"log in with CTFD_TOKEN={TOKEN}")))
    assert TOKEN in lane.waiting[0].detail  # the deck's own
    rows = full(deck, lane, **how)
    assert rows[0] == f"◆ waiting for you: {BOX_SHOWN}" and rows[3] == "then: log in with CTFD_TOKEN=[redacted]"
    assert TOKEN not in "\n".join(rows) and JWT not in "\n".join(rows)


def test_the_card_on_the_screen_shows_no_credential_of_an_approval_calm_or_full():
    deck, app, lane = one_lane("simple")
    deck.report("L01", TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, BOX)))
    deck.report("L01", TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, f"log in with CTFD_TOKEN={TOKEN}")))

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        assert inside(app)[0] == f"◆ waiting for you: {BOX_SHOWN}"
        assert TOKEN not in "\n".join(screen_lines(app)) and JWT not in "\n".join(screen_lines(app))
        await press(pilot, "ctrl+o")
        assert view.details
        shown = one_line(card(app))
        assert f"◆ waiting for you: {BOX_SHOWN} 1 /approve" in shown and "then: log in with CTFD_TOKEN=[redacted]" in shown
        assert TOKEN not in "\n".join(screen_lines(app)) and JWT not in "\n".join(screen_lines(app))

    drive(app, script, BIG)


# ---------------------------------------------------------------------- the card on the screen


@pytest.mark.parametrize("size", [BIG, NARROW], ids=["254x71", "120x36"])
def test_in_the_simple_layout_four_things_at_once_are_a_card_of_five_rows(size):
    deck, app, lane = four_at_once("simple")

    async def script(pilot):
        view = await open_focus(pilot, app, lane.id)
        assert not view.details
        rows = card(app)
        assert len(rows) == 5 and rows[0].startswith("╭─ needs you now ─") and rows[-1].startswith("╰─")
        assert inside(app) == FOUR_CALM
        text = "\n".join(rows)
        for absent in ("/kill", "/approve", "/hint", "The budget shrinks", "press a number"):
            assert absent not in text, absent
        box, log = view.query_one("#now-scroll"), view.query_one("#transcript")
        assert box.max_scroll_y == 0 and box.region.y == log.region.bottom  # nothing to scroll, and it sits under the transcript
        row = view.query_one("#now").region.y
        budget = theme.alert_colors(AlertKind.BUDGET)[1].lower()
        assert color_of(app, "needs you now", row) == budget and color_of(app, "╭", row) == budget  # the most urgent alert's, as on the full card
        assert footer_line(app).strip().startswith("1-9 answer  esc lanes")  # the key line says a number answers: the card has no row for it

    drive(app, script, size)


def test_in_the_deck_layout_the_approval_and_its_answers_are_in_view_on_a_card_too_tall_for_its_half_and_the_card_scrolls():
    deck, app, lane = four_at_once("deck")

    async def script(pilot):
        view = await open_focus(pilot, app, lane.id)
        assert view.details
        box, pane = view.query_one("#now-scroll"), view.query_one("#talk-pane")
        assert box.region.height <= (pane.content_region.height + 1) // 2 and view.query_one("#transcript").region.height >= 3
        assert view.query_one("#now").region.height > box.region.height and box.max_scroll_y > 0  # taller than its box: it scrolls
        rows = card(app)
        assert rows[0].startswith("╭─ needs you now ─")
        shown = one_line(rows)
        assert shown.startswith("╭─ needs you now ─") and f"{ASKS} 1 /approve more budget 0 /decline stop the lane ▲ Budget" in shown
        assert "press a number to answer" not in shown  # the card's last row is below its box
        box.scroll_end(animate=False)
        await pilot.pause()
        shown = one_line(card(app))
        assert "press a number to answer (chat box empty), / to pick a command, or write a message" in shown and "/approve" not in shown
        assert not box.can_focus
        await press(pilot, "tab")  # tab still goes chat -> files, not to the card
        assert app.focused is view.query_one("#files")

    drive(app, script, NARROW)


def test_ctrl_o_turns_the_calm_card_into_the_full_one_and_back():
    deck, app, lane = four_at_once("simple")

    async def script(pilot):
        view = await open_focus(pilot, app, lane.id)
        assert inside(app) == FOUR_CALM
        await press(pilot, "ctrl+o")
        assert view.details and status_line(app).strip().endswith(DETAILS_ON)
        shown = one_line(card(app))
        assert view.query_one("#now-scroll").max_scroll_y == 0  # at this size all of it is in view
        assert f"{ASKS} 1 /approve more budget 0 /decline stop the lane" in shown
        for one in lane.alerts:  # every alert: its label and its whole reason
            assert f"▲ {one.kind.label} {' '.join(untrusted(one.reason, one_line=True).split())}" in shown, one.kind
        for command in ("/kill kill the lane", "/hint You are repeating cd /work && python3", "/kill kill and re-queue fresh",
                        "/hint This is a 0-point challenge", "/escalate", "/redirect", "press a number to answer"):
            assert command in shown, command
        assert len(card(app)) > 12 and "ctrl+o shows all" not in shown
        await press(pilot, "ctrl+o")
        assert not view.details and status_line(app).strip().endswith(DETAILS_OFF)
        assert inside(app) == FOUR_CALM and len(card(app)) == 5

    drive(app, script, BIG)


def test_in_the_deck_layout_the_card_is_the_full_one_until_ctrl_o_and_the_layout_sets_it_until_then():
    deck, app, lane = four_at_once("deck")

    async def script(pilot):
        view = await open_focus(pilot, app, lane.id)
        assert "/approve" in one_line(card(app)) and len(card(app)) > 12
        await send(pilot, app, "/layout simple")
        assert inside(app) == FOUR_CALM
        await send(pilot, app, "/layout deck")
        assert "/approve" in one_line(card(app))
        await press(pilot, "ctrl+o")  # by hand, in the deck layout: the calm card there too
        assert not view.details and inside(app) == FOUR_CALM

    drive(app, script, BIG)


def test_the_numbers_on_the_calm_card_answer_as_before():
    deck, app, lane = four_at_once("simple")

    async def more(pilot):
        await open_focus(pilot, app, lane.id)
        assert inside(app)[1] == "  1 more budget   0 stop the lane"
        await press(pilot, "1")
        assert lane.token_cap == 600_000 and lane.state is LaneState.RUNNING and lane.pending is None
        rows = inside(app)  # the next question: the loop, with its own numbers
        assert rows[0].startswith("▲ Loop: The same command ran") and rows[1].startswith('  1 hint "You are repeating cd /work && python3')
        assert rows[2] == "  also: past its effort budget · stalled   ctrl+o shows all"
        await press(pilot, "2")
        assert isinstance(app.screen, KillPrompt) and not lane.finished

    drive(app, more, BIG)

    deck, app, lane = four_at_once("simple")

    async def stop(pilot):
        await open_focus(pilot, app, lane.id)
        await press(pilot, "0")
        assert lane.finished and lane.state is LaneState.STOPPED and lane.token_cap == 400_000
        assert region_text(app, "#now-scroll").strip().endswith("this lane has ended; esc goes back to the lanes")
        assert "needs you now" not in region_text(app, "#talk-pane")  # one line, no border

    drive(app, stop, BIG)


def test_answer_1_of_a_loop_sends_the_hint_the_card_quotes_and_the_card_then_shows_it_as_sent():
    deck, app, lane = one_lane("simple", watch=True)
    for _ in range(3):
        deck.report("L01", TurnReport(action="python3 solve.py", output="no"))
    hint = "You are repeating python3 solve.py: it gives the same result. Try something else."

    async def script(pilot):
        view = await open_focus(pilot, app, "L01")
        assert inside(app)[1] == f'  1 hint "{hint[:48]}…"   2 kill and re-queue fresh   /dismiss not a problem'
        await press(pilot, "1")
        assert lane.hints == [hint] and not lane.alerts
        assert inside(app) == [f"› sent, not read yet: {hint}"] and len(card(app)) == 3
        row = view.query_one("#now").region.y
        assert color_of(app, "needs you now", row) == theme.BORDER.lower()  # nothing to answer: the plain border
        deck.report("L01", TurnReport(action="python3 other.py", output="yes", hints_taken=1))  # the lane reads it: nothing is open
        app.refresh_view()
        await pilot.pause()
        assert not view.query_one("#now").display and not view.query_one("#now-scroll").display
        assert "needs you now" not in region_text(app, "#talk-pane")

    drive(app, script, BIG)


def test_a_calm_row_longer_than_the_card_is_cut_at_its_edge_and_never_wraps():
    deck, app, lane = four_at_once("simple")

    async def script(pilot):
        await open_focus(pilot, app, lane.id)
        await press(pilot, "1")  # the loop is the question: its reason quotes five lines of command
        rows = card(app)
        assert len(rows) == 5
        width = len(rows[0])
        assert all(len(row) == width for row in rows)
        assert rows[1].startswith("│ ▲ Loop: The same command ran 6 times in the last 6 turns: cd /work && python3") and rows[1].endswith("… │")
        assert rows[3] == "│   also: past its effort budget · stalled   ctrl+o shows all".ljust(width - 1) + "│"

    drive(app, script, NARROW)


HINTED = alert(AlertKind.HINT, "The description hints at slow-scan TV.", ("r", "Redirect with the hinted technique", "Decode it as SSTV and read the picture"),
               ("h", "Hint", "Think slow-scan TV, not stereo tricks"))
HINTED_WHOLE = ('  1 redirect with the hinted technique "Decode it as SSTV and read the picture"   2 hint "Think slow-scan TV, not stereo tricks"'
                "   /dismiss not a problem")
HINTED_BARE = "  1 redirect with the hinted technique   2 hint   /dismiss not a problem"  # with no quote


def test_the_calm_cards_answers_are_fitted_to_the_card_as_it_is_drawn_and_again_when_its_width_changes():
    deck, app, lane = one_lane("simple")
    deck.report("L01", TurnReport(action="write solve.py", files=(FileChange("solve.py", "+++ b/solve.py\n+print(1)\n", status="added"),)))

    async def script(pilot):
        app.open_lane("L01")  # nothing open on it: no card, and its box is not shown
        await pilot.pause()
        view = app.screen
        box = view.query_one("#now-scroll")
        assert not box.display and view.query_one("#files-pane").display
        raise_alerts(deck, HINTED)
        app.refresh_view()  # one redraw, as the console's timer does: the box is first laid out after it
        await pilot.pause()
        assert box.display and box.region.width < len(HINTED_WHOLE)  # beside the files pane the card is narrower than its answers
        row = inside(app)[1]  # both numbers in view: the quotes gave way, and the edge cuts what is left
        assert row.startswith("  1 redirect with the hinted technique   2 hint   /dismiss") and row.endswith("…") and HINTED_BARE.startswith(row[:-1])
        await pilot.resize_terminal(300, 40)
        await pilot.pause()
        assert inside(app)[1] == HINTED_WHOLE  # room for them: no redraw was asked for
        await pilot.resize_terminal(220, 40)
        await pilot.pause()
        row = inside(app)[1]
        assert row.startswith('  1 redirect with the hinted technique "Decode it as') and row.endswith("…\"   /dismiss not a problem")
        assert '2 hint "Think slow-' in row and len(row) <= box.region.width - 4 and "pictu" not in row

    drive(app, script, NARROW)


def test_another_lanes_card_starts_at_its_first_row_and_the_calm_card_takes_the_colours_of_a_new_theme():
    deck, app, lane = four_at_once("deck")
    deck.release([Challenge("d", "Other", "misc", 100)], [QueueEntry("d", "glm")])
    (other,) = deck.lanes_on("d")
    deck.report(other.id, TurnReport(action="ls", pending=Pending(PendingKind.LIVE_BOX, "connect to the live instance")))
    why = "It has read the same three files in turn for a while now, and nothing it found in them changed what it does next. "
    deck.report(other.id, TurnReport(turn=False, alerts=tuple(alert(kind, why * 2, *STALL[1:]) for kind in (
        AlertKind.LOOP, AlertKind.EFFORT, AlertKind.HINT, AlertKind.DIRECTION, AlertKind.STALL))))

    async def script(pilot):
        view = await open_focus(pilot, app, lane.id)
        box = view.query_one("#now-scroll")
        box.scroll_end(animate=False)
        await pilot.pause()
        assert box.scroll_y > 0
        await open_focus(pilot, app, other.id)
        assert box.max_scroll_y > 0 and box.scroll_y == 0  # a card that scrolls too, at its first row
        assert one_line(card(app)).startswith("╭─ needs you now ─") and "◆ waiting for you: connect to the live instance" in one_line(card(app))
        await press(pilot, "ctrl+o")
        assert inside(app) == [
            "◆ waiting for you: connect to the live instance",
            "  1 use the live box   0 stay off it",
            "  also: looping · past its effort budget · ignores the hin…",  # cut at the card's edge
        ]
        row = view.query_one("#now").region.y
        before = color_of(app, "needs you now", row)
        assert before == theme.alert_colors(AlertKind.LOOP)[1].lower()
        await send(pilot, app, "/theme nord")
        after = color_of(app, "needs you now", row)
        assert after == theme.alert_colors(AlertKind.LOOP)[1].lower() != before
        assert color_of(app, "◆ waiting for you", row + 1) == theme.PURPLE.lower()

    drive(app, script, NARROW)


def test_on_a_narrow_terminal_the_card_keeps_its_compact_form_with_details_off():
    deck, app, lane = four_at_once("simple")

    async def script(pilot):
        view = await open_focus(pilot, app, lane.id)
        assert view.compact and view.details
        before = card(app)
        text = one_line(before)
        assert text.startswith("╭─ needs you now ─") and "1 /approve more budget" in text and "0 /decline stop the lane" in text
        assert view.query_one("#now-scroll").region.bottom <= view.query_one("#transcript").region.y  # above its transcript
        await press(pilot, "ctrl+o")
        assert not view.details and card(app) == before and not view.query_one("#now", Static).has_class("-calm")

    drive(app, script, PHONE)
