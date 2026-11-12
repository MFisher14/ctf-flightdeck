"""A light model's route of a challenge on the deck and the console (core/deck.record_route,
console/views.py): kept beside the board's category, never in its place; the guess shown with a
question mark, the family in the why lines and the lane filter; logged as a route event and
noted on its lane."""

from __future__ import annotations

from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.console import views
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import Challenge, DeckConfig, EventKind
from ctf_flightdeck.light import CATEGORY

FLAG = r"t\{[a-z0-9_]+\}"


class Idle:
    """A driver that does nothing: the views read the deck alone."""

    def attach(self, deck): ...
    def start(self, lane, challenge): ...
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def rejected(self, lane, flag): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...


def board() -> tuple[Deck, Challenge, Challenge]:
    deck = Deck(DeckConfig(event="t", flag_format=FLAG, models=("small",)), Idle(), RunClock(), lambda cid, flag: None)
    routed = Challenge("routed", "Routed", "warmup", 100, description="Hi.")
    plain = Challenge("plain", "Plain", "pwn", 100, description="Hi.")
    deck.release([routed, plain], [QueueEntry("routed", "small"), QueueEntry("plain", "small")])
    return deck, routed, plain


def lane_of(deck: Deck, cid: str):
    return next(x for x in deck.lanes.values() if x.challenge_id == cid)


def test_a_route_is_kept_beside_the_boards_category_logged_and_noted_on_its_lane():
    deck, routed, _ = board()
    lane = lane_of(deck, "routed")
    deck.record_route("routed", family="binary-exploitation", category="pwn", by="openai light/m", lane_id=lane.id)
    assert (routed.category, routed.category_guess, routed.family) == ("warmup", "pwn", "binary-exploitation")
    (event,) = [e for e in deck.events if e.kind is EventKind.ROUTE]
    assert (event.lane, event.challenge) == (lane.id, "routed")
    assert event.data == {"family": "binary-exploitation", "category": "pwn", "board_category": "warmup", "by": "openai light/m"}
    assert event.text == ("light model (openai light/m) routed Routed: family binary-exploitation, category pwn? (a guess: "
                          "the board names none flightdeck knows)")
    assert lane.actions[-1].text == ("light model (openai light/m) routed it: family binary-exploitation, category pwn? (a "
                                     "guess: the board names none flightdeck knows)")
    deck.record_route("routed", by="openai light/m", lane_id=lane.id)  # nothing to record: nothing logged
    assert len([e for e in deck.events if e.kind is EventKind.ROUTE]) == 1


def test_the_console_shows_a_guess_with_a_question_mark_beside_the_boards_category_and_the_family():
    deck, routed, plain = board()
    deck.record_route("routed", family="binary-exploitation", category="pwn", by="openai light/m", lane_id="L01")
    cell = views.category_cell(routed)
    assert cell.plain == "pwn?" and "italic" in str(cell.style)
    assert views.category_cell(plain).plain == "pwn"
    why = views.challenge_why(deck, routed).plain
    assert "warmup" in why and "light model: family binary-exploitation, category pwn?" in why
    assert "light model" not in views.challenge_why(deck, plain).plain
    lane, other = lane_of(deck, "routed"), lane_of(deck, "plain")
    assert views.lane_why(deck, lane).plain.startswith(f"▌{lane.id} binary-exploitation · plan: ")
    assert views.lane_why(deck, other).plain.startswith(f"▌{other.id} plan: ")
    assert views.lane_matches(deck, lane, "binary-exploitation") and views.lane_matches(deck, lane, "pwn")
    assert not views.lane_matches(deck, other, "binary-exploitation")
    width = dict((key, w) for key, _, w, _ in views.BOARD_COLUMNS)["cat"]
    assert all(len(f"{choice.id}{views.GUESSED}") <= width for choice in CATEGORY.choices)  # every guess fits whole
