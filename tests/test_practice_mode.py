"""Practice mode: an archived board with a release timeline, and a run scored from its event log.

Every board is a real folder in tmp_path, loaded with the real board loader; the deck, the
event log, its file and the answers file are real. The driver is a stand-in that does no
work (lane work is not under test here) and the clock is turned by hand. Names, flags and
events are synthetic.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ctf_flightdeck import practice_cli, practice_set
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import ME, ChallengeStatus, DeckConfig, EventKind
from ctf_flightdeck.eventlog import EventLog
from ctf_flightdeck.platform.manual import AnswerVerifier, cannot_check, load_board
from ctf_flightdeck.practice_mode import (
    Release,
    ScoreError,
    Timeline,
    TimelineError,
    Wave,
    load_timeline,
    score,
    scorecard,
)

FLAG_FORMAT = r"t\{\w+\}"
MODELS = ("small", "big")
# id: (name, category, points)
CHALLENGES = {
    "alpha": ("Alpha Gate", "crypto", 50),
    "bravo": ("Bravo Box", "web", 200),
    "charlie": ("Charlie Chart", "misc", 100),
    "delta": ("Delta Drift", "rev", 300),
}
FLAGS = {cid: f"t{{{cid}_sample_flag}}" for cid in CHALLENGES}
WRONG = "t{not_the_flag}"
WAVES = {"waves": [{"at": 7200, "ids": ["delta"]}, {"at": 600, "ids": ["charlie"]}]}  # out of order on purpose


def sha(flag: str) -> str:
    return hashlib.sha256(flag.encode()).hexdigest()


def make_board(
    folder: Path,
    challenges: dict[str, tuple[str, str, int]] = CHALLENGES,
    *,
    answers: dict[str, str] | None = FLAGS,
    timeline: dict | str | None = None,
) -> Path:
    """A board folder: one directory per challenge, board.json, and optionally the answers
    file (hashes of `answers`) and a timeline.json (a dict as JSON, a str as is)."""
    folder.mkdir(parents=True, exist_ok=True)
    for cid, (name, category, points) in challenges.items():
        (folder / cid).mkdir()
        (folder / cid / "challenge.json").write_text(json.dumps({"name": name, "category": category, "points": points}))
        (folder / cid / "notes.txt").write_text("synthetic handout\n")
    (folder / "board.json").write_text(json.dumps({"event": "Sample Archive", "flag_format": FLAG_FORMAT}))
    if answers is not None:
        (folder / "answers.sha256.json").write_text(json.dumps({cid: sha(flag) for cid, flag in answers.items()}))
    if timeline is not None:
        (folder / "timeline.json").write_text(timeline if isinstance(timeline, str) else json.dumps(timeline))
    return folder


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def now(self) -> float:
        return self.t


class Driver:
    """Does no lane work; notes which challenges the deck started lanes on."""

    def __init__(self) -> None:
        self.started: list[str] = []

    def attach(self, deck): ...
    def start(self, lane, challenge):
        self.started.append(challenge.id)
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def rejected(self, lane, flag): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...


def make_deck(board, *, verify=None, max_lanes=4) -> tuple[Deck, Clock, Driver]:
    clock, driver = Clock(), Driver()
    if verify is None:
        verify = AnswerVerifier(board.answers) if board.answers else cannot_check
    config = DeckConfig(event=board.event, max_lanes=max_lanes, flag_format=board.flag_format, models=MODELS)
    return Deck(config, driver, clock, verify), clock, driver


def cheapest_first(board):
    """entries_for as a run builds it: the wave's challenges, fewest points first."""
    points = {item.challenge.id: item.challenge.points for item in board.challenges}

    def entries_for(ids: list[str]) -> list[QueueEntry]:
        return [QueueEntry(cid, MODELS[0]) for cid in sorted(ids, key=lambda cid: points[cid])]

    return entries_for


def releases(deck: Deck) -> list[str]:
    return [event.data["label"] for event in deck.events if event.kind is EventKind.RELEASE]


# ---------------------------------------------------------------------- loading the timeline


def test_without_a_timeline_the_whole_board_goes_out_at_the_start(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    assert load_timeline(board) == Timeline((Wave(0.0, ("alpha", "bravo", "charlie", "delta")),))


def test_the_boards_timeline_gives_waves_in_time_order_and_the_rest_at_the_start(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    assert [item.challenge.id for item in board.challenges] == list(CHALLENGES)  # the file does not disturb the board
    assert load_timeline(board) == Timeline(
        (Wave(0.0, ("alpha", "bravo")), Wave(600.0, ("charlie",)), Wave(7200.0, ("delta",)))
    )


def test_unlisted_challenges_join_the_wave_at_the_start_after_its_own(tmp_path):
    timeline = {"waves": [{"at": 90.5, "ids": ["alpha"]}, {"at": 0, "ids": ["delta", "charlie"]}]}
    board = load_board(make_board(tmp_path / "archive", timeline=timeline))
    assert load_timeline(board) == Timeline((Wave(0.0, ("delta", "charlie", "bravo")), Wave(90.5, ("alpha",))))


def test_an_empty_list_of_waves_puts_everything_out_at_the_start(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline={"waves": []}))
    assert load_timeline(board) == Timeline((Wave(0.0, ("alpha", "bravo", "charlie", "delta")),))


def test_a_named_timeline_wins_over_the_boards_and_may_live_anywhere(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    elsewhere = tmp_path / "kept" / "drops.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text(json.dumps({"waves": [{"at": 30, "ids": ["bravo"]}]}))
    link = tmp_path / "link.json"
    link.symlink_to(elsewhere)  # the player named it, so a symlink is followed
    expected = Timeline((Wave(0.0, ("alpha", "charlie", "delta")), Wave(30.0, ("bravo",))))
    assert load_timeline(board, elsewhere) == expected
    assert load_timeline(board, link) == expected


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        ("{not json", "is not valid JSON"),
        ("[]", "must be a JSON object"),
        ('{"waves": [], "wave": []}', 'unknown key "wave" (known: waves)'),
        ("{}", '"waves" is missing'),
        ('{"waves": {"at": 0}}', '"waves" must be a list'),
        ('{"waves": [3]}', '"waves"[0] must be an object with "at" and "ids"'),
        ('{"waves": [{"at": 1, "ids": ["alpha"], "label": "x"}]}', '"waves"[0]: unknown key "label" (known: at, ids)'),
        ('{"waves": [{"ids": ["alpha"]}]}', '"waves"[0]: "at" is missing'),
        ('{"waves": [{"at": -1, "ids": ["alpha"]}]}', '"waves"[0]: "at" must be a number of seconds'),
        ('{"waves": [{"at": true, "ids": ["alpha"]}]}', '"waves"[0]: "at" must be a number of seconds'),
        ('{"waves": [{"at": "1h", "ids": ["alpha"]}]}', '"waves"[0]: "at" must be a number of seconds'),
        ('{"waves": [{"at": NaN, "ids": ["alpha"]}]}', '"waves"[0]: "at" must be a number of seconds'),
        ('{"waves": [{"at": 1e999, "ids": ["alpha"]}]}', '"waves"[0]: "at" must be a number of seconds'),
        ('{"waves": [{"at": 1' + "0" * 400 + ', "ids": ["alpha"]}]}', '"waves"[0]: "at" must be a number of seconds'),
        ('{"waves": [{"at": 1}]}', '"waves"[0]: "ids" is missing'),
        ('{"waves": [{"at": 1, "ids": []}]}', '"waves"[0]: "ids" must be a non-empty list'),
        ('{"waves": [{"at": 1, "ids": "alpha"}]}', '"waves"[0]: "ids" must be a non-empty list'),
        ('{"waves": [{"at": 1, "ids": ["alpha", 7]}]}', '"waves"[0]: "ids"[1] must be a challenge id'),
        ('{"waves": [{"at": 1, "ids": ["zulu", "alpha", "yankee"]}]}', 'not on the board: "zulu", "yankee"'),
        ('{"waves": [{"at": 1, "ids": ["alpha", "alpha"]}]}', '"waves"[0] lists "alpha" twice'),
        (
            '{"waves": [{"at": 1, "ids": ["alpha"]}, {"at": 2, "ids": ["bravo", "alpha"]}]}',
            '"waves"[1] lists "alpha" again; it is already in "waves"[0]',
        ),
        (
            '{"waves": [{"at": 5, "ids": ["alpha"]}, {"at": 5.0, "ids": ["bravo"]}]}',
            '"waves"[1] is at 5 s, like "waves"[0]; put their ids in one wave',
        ),
        ('{"waves": [], "waves": []}', 'has the key "waves" twice'),
    ],
)
def test_a_bad_timeline_names_the_file_and_the_problem(tmp_path, content, problem):
    board = load_board(make_board(tmp_path / "archive", timeline=content))
    with pytest.raises(TimelineError) as caught:
        load_timeline(board)
    message = str(caught.value)
    assert message.startswith(str(board.challenges[0].handout.parent / "timeline.json") + ":"), message
    assert problem in message


def test_a_missing_named_timeline_is_an_error_not_the_whole_board_at_once(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    with pytest.raises(TimelineError, match="no such file"):
        load_timeline(board, tmp_path / "nowhere.json")


def test_a_symlinked_timeline_in_the_board_is_refused(tmp_path):
    folder = make_board(tmp_path / "archive")
    real = tmp_path / "real.json"
    real.write_text(json.dumps(WAVES))
    (folder / "timeline.json").symlink_to(real)
    with pytest.raises(TimelineError, match="is a symlink; flightdeck does not follow symlinks in a board"):
        load_timeline(load_board(folder))


def test_a_dangling_symlinked_timeline_is_refused_not_ignored(tmp_path):
    folder = make_board(tmp_path / "archive")
    (folder / "timeline.json").symlink_to(tmp_path / "gone.json")
    with pytest.raises(TimelineError, match="is a symlink"):
        load_timeline(load_board(folder))


def test_a_timeline_that_is_a_directory_is_refused(tmp_path):
    folder = make_board(tmp_path / "archive")
    (folder / "timeline.json").mkdir()
    with pytest.raises(TimelineError, match="is not a regular file"):
        load_timeline(load_board(folder))


def test_an_oversized_timeline_is_refused_before_it_is_parsed(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline="[" + " " * 1_000_001 + "]"))
    with pytest.raises(TimelineError, match="too big for a timeline"):
        load_timeline(board)


def test_a_timeline_that_is_not_utf8_is_an_error(tmp_path):
    folder = make_board(tmp_path / "archive")
    (folder / "timeline.json").write_bytes(b'{"waves": [{"at": 1, "ids": ["\xff"]}]}')
    with pytest.raises(TimelineError, match="is not UTF-8 text"):
        load_timeline(load_board(folder))


def test_a_timeline_with_a_byte_order_mark_loads(tmp_path):
    folder = make_board(tmp_path / "archive")
    (folder / "timeline.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(WAVES).encode())
    assert [wave.at for wave in load_timeline(load_board(folder)).waves] == [0.0, 600.0, 7200.0]


def test_untrusted_text_in_a_timeline_error_cannot_reach_the_terminal_raw(tmp_path):
    nasty = "zulu\x1b[2J\nforged line‮"
    board = load_board(make_board(tmp_path / "archive", timeline={"waves": [{"at": 1, "ids": [nasty]}]}))
    with pytest.raises(TimelineError) as caught:
        load_timeline(board)
    message = str(caught.value)
    assert "\x1b" not in message and "\n" not in message and "‮" not in message
    assert "^[[2J" in message and "forged line" in message


# ---------------------------------------------------------------------- releasing waves


def test_each_wave_goes_out_on_the_deck_at_its_time(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    deck, clock, driver = make_deck(board)
    release = Release(deck, board, load_timeline(board), cheapest_first(board))
    assert (release.next_at, release.done) == (0.0, False)
    assert release.tick() == [Wave(0.0, ("alpha", "bravo"))]
    assert set(deck.challenges) == {"alpha", "bravo"} and driver.started == ["alpha", "bravo"]
    assert releases(deck) == ["Wave 1 of 3"]
    clock.t = 599.9
    assert release.tick() == []
    assert "charlie" not in deck.challenges and releases(deck) == ["Wave 1 of 3"]
    assert release.next_at == 600.0
    clock.t = 600.0
    assert release.tick() == [Wave(600.0, ("charlie",))]
    assert "charlie" in deck.challenges and driver.started[-1] == "charlie"
    assert [wave.at for wave in release.waiting] == [7200.0] and not release.done
    clock.t = 7300.0
    assert release.tick() == [Wave(7200.0, ("delta",))]
    assert releases(deck) == ["Wave 1 of 3", "Wave 2 of 3", "Wave 3 of 3"]
    assert release.done and release.next_at is None and release.waiting == ()
    assert [wave.at for wave in release.released] == [0.0, 600.0, 7200.0]
    release_events = [event for event in deck.events if event.kind is EventKind.RELEASE]
    assert [event.at for event in release_events] == [0.0, 600.0, 7300.0]
    assert [event.data["challenges"] for event in release_events] == [["alpha", "bravo"], ["charlie"], ["delta"]]


def test_a_wave_never_goes_out_twice(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    deck, clock, driver = make_deck(board)
    release = Release(deck, board, load_timeline(board), cheapest_first(board))
    clock.t = 600.0
    first = release.tick()
    assert [wave.at for wave in first] == [0.0, 600.0]
    events = len(deck.events)
    for _ in range(3):
        assert release.tick() == []
    clock.t = 7200.0
    assert release.tick() == [Wave(7200.0, ("delta",))]
    clock.t = 1e9
    assert release.tick() == []
    assert releases(deck) == ["Wave 1 of 3", "Wave 2 of 3", "Wave 3 of 3"]
    assert sorted(driver.started) == sorted(CHALLENGES)  # one lane each, never a second release
    assert len([e for e in deck.events[events:] if e.kind is EventKind.RELEASE]) == 1


def test_waves_overdue_at_one_tick_go_out_in_time_order_each_on_its_own(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    deck, clock, _ = make_deck(board)
    release = Release(deck, board, load_timeline(board), cheapest_first(board))
    clock.t = 10_000.0
    assert [wave.at for wave in release.tick()] == [0.0, 600.0, 7200.0]
    assert releases(deck) == ["Wave 1 of 3", "Wave 2 of 3", "Wave 3 of 3"]
    assert release.done


def test_a_board_without_a_timeline_goes_out_as_one_release_at_the_first_tick(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    deck, clock, driver = make_deck(board)
    release = Release(deck, board, load_timeline(board), cheapest_first(board))
    clock.t = 3.0
    assert release.tick() == [Wave(0.0, ("alpha", "bravo", "charlie", "delta"))]
    assert releases(deck) == ["Board"]
    assert driver.started == ["alpha", "charlie", "bravo", "delta"]  # entries_for's order: fewest points first


def test_the_queue_follows_entries_for_and_an_id_without_an_entry_is_only_put_on_the_board(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    deck, _, driver = make_deck(board, max_lanes=1)

    def entries_for(ids):
        return [QueueEntry("delta", MODELS[0]), QueueEntry("alpha", MODELS[0])]  # bravo and charlie: none

    Release(deck, board, load_timeline(board), entries_for).tick()
    assert driver.started == ["delta"]
    assert [entry.challenge for entry in deck.queue] == ["alpha"]
    assert set(deck.challenges) == set(CHALLENGES)
    assert deck.challenges["bravo"].status is ChallengeStatus.NEW


def test_a_wave_whose_release_fails_raises_and_is_not_tried_again(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    deck, clock, _ = make_deck(board)

    def entries_for(ids):
        model = "no-such-model" if "charlie" in ids else MODELS[0]  # not in the ladder: the deck refuses it
        return [QueueEntry(cid, model) for cid in ids]

    release = Release(deck, board, load_timeline(board), entries_for)
    release.tick()
    clock.t = 600.0
    with pytest.raises(ValueError, match="no-such-model"):
        release.tick()
    assert release.tick() == []  # not retried
    assert "charlie" not in deck.challenges and [wave.at for wave in release.released] == [0.0]
    clock.t = 7200.0
    assert release.tick() == [Wave(7200.0, ("delta",))]  # the next wave still goes out on time


def test_entries_for_challenges_outside_the_wave_are_refused_before_the_deck_sees_them(tmp_path):
    board = load_board(make_board(tmp_path / "archive", timeline=WAVES))
    deck, _, _ = make_deck(board)
    every = [QueueEntry(cid, MODELS[0]) for cid in CHALLENGES]
    release = Release(deck, board, load_timeline(board), lambda ids: every)
    with pytest.raises(ValueError, match='not in this wave: "charlie", "delta"'):
        release.tick()
    assert deck.challenges == {} and releases(deck) == []


def test_the_deck_gets_copies_so_the_board_stays_as_loaded(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    deck, clock, _ = make_deck(board)
    Release(deck, board, load_timeline(board), cheapest_first(board)).tick()
    deck.report("L01", TurnReport(action="solve", flag=FLAGS["alpha"]))
    deck.apply(iv.Approve("L01"))
    assert deck.challenges["alpha"].status is ChallengeStatus.SOLVED and deck.challenges["alpha"].solves == 1
    original = board.challenges[0].challenge
    assert original.id == "alpha" and original.status is ChallengeStatus.NEW and original.solves == 0
    assert deck.challenges["alpha"] is not original


@pytest.mark.parametrize(
    ("waves", "problem"),
    [
        ((Wave(0.0, ("alpha", "bravo", "charlie")),), 'leaves out challenges on the board, so they would never be released: "delta"'),
        ((Wave(0.0, ("alpha", "bravo", "charlie", "delta", "zulu")),), 'names "zulu", which is not on the board'),
        ((Wave(0.0, ("alpha", "bravo")), Wave(5.0, ("bravo", "charlie", "delta"))), '"bravo" is in more than one wave'),
        ((Wave(-5.0, ("alpha", "bravo", "charlie", "delta")),), "a wave's time must be a number of seconds"),
    ],
)
def test_a_hand_made_timeline_must_hold_the_board_exactly_once(tmp_path, waves, problem):
    board = load_board(make_board(tmp_path / "archive"))
    deck, _, _ = make_deck(board)
    with pytest.raises(TimelineError) as caught:
        Release(deck, board, Timeline(waves), cheapest_first(board))
    assert problem in str(caught.value)


# ---------------------------------------------------------------------- scoring a run


class Played:
    """A run on the archive, logged to a real events.jsonl: what happened, written out by hand."""

    def __init__(self, tmp_path: Path, *, answers=FLAGS, verify=None, all_priced=False) -> None:
        self.folder = make_board(tmp_path / "archive", answers=answers, timeline=WAVES)
        self.board = load_board(self.folder)
        self.deck, self.clock, _ = make_deck(self.board, verify=verify)
        self.dir = tmp_path / "runs" / "20261110-200000"
        self.log = EventLog(self.dir / "events.jsonl")
        self.log.attach(self.deck)
        self.release = Release(self.deck, self.board, load_timeline(self.board), cheapest_first(self.board))
        self.l02_dollars = 0.02 if all_priced else None  # L02's model has no price unless all_priced

    def at(self, t: float) -> Played:
        self.clock.t = t
        self.release.tick()
        return self

    def play(self) -> Played:
        deck = self.deck
        self.at(0)  # alpha -> L01, bravo -> L02
        self.at(60)
        deck.report("L01", TurnReport(action="ls", tokens=1200, dollars=0.004))
        deck.report("L01", TurnReport(action="python3 solve.py", tokens=800, dollars=0.003, flag=FLAGS["alpha"]))
        self.at(130)
        deck.apply(iv.Approve("L01"))  # correct: alpha solved at 130
        self.at(200)
        deck.report("L02", TurnReport(action="ffuf -w words", tokens=5000, dollars=self.l02_dollars, flag=WRONG))
        deck.apply(iv.Approve("L02"))  # a wrong submission
        deck.apply(iv.Hint("L02", "read the handout source first"))
        deck.apply(iv.Approve("L02"))  # refused: nothing waits for approval, so not counted
        self.at(300)
        deck.apply(iv.Fork("L02", "read the source"))  # L03 on bravo, model big
        self.at(600)  # charlie -> L04
        deck.report("L04", TurnReport(action="file chart.bin", tokens=300, dollars=0.001))
        self.at(700)
        deck.apply(iv.Kill("L04", requeue=False))
        self.at(800)
        deck.report("L03", TurnReport(action="cat app.py", tokens=2000, dollars=0.05, flag=FLAGS["bravo"]))
        self.at(900)
        deck.apply(iv.Approve("L03"))  # correct: bravo solved at 900; L02 stops
        self.at(1000)
        return self

    def close(self) -> Path:
        self.log.close()
        return self.log.path


@pytest.fixture
def played(tmp_path) -> Played:
    return Played(tmp_path).play()


def test_the_score_has_the_solves_points_and_first_solve_time(played):
    result = score(played.close(), played.board)
    assert result.solved == ("alpha", "bravo")
    assert (result.points, result.possible) == (250, 650)
    assert result.first_solve_at == 130.0
    alpha, bravo = result.per_challenge["alpha"], result.per_challenge["bravo"]
    assert (alpha.solved_by, alpha.solved_at, alpha.released_at, alpha.time_to_solve) == ("L01", 130.0, 0.0, 130.0)
    assert (bravo.solved_by, bravo.solved_at, bravo.checked) == ("L03", 900.0, "answers")
    assert result.event == "Sample Archive" and result.answers == played.board.answers
    assert result.ended_at == 900.0  # the last event: the tick at 1000 put nothing out


def test_every_challenge_on_the_board_has_a_line_in_board_order(played):
    result = score(played.close(), played.board)
    assert list(result.per_challenge) == list(CHALLENGES)
    charlie, delta = result.per_challenge["charlie"], result.per_challenge["delta"]
    assert (charlie.released_at, charlie.solved, charlie.lanes) == (600.0, False, ("L04",))
    assert result.lanes["L04"].state == "killed"
    assert (delta.released_at, delta.solved, delta.lanes, delta.tokens, delta.dollars) == (None, False, (), 0, 0.0)
    assert (delta.name, delta.category, delta.points) == ("Delta Drift", "rev", 300)


def test_the_cost_of_a_solve_counts_every_lane_on_it(tmp_path):
    played = Played(tmp_path, all_priced=True).play()
    result = score(played.close(), played.board)
    alpha, bravo = result.per_challenge["alpha"], result.per_challenge["bravo"]
    assert (alpha.tokens, alpha.turns) == (2000, 2) and alpha.dollars == pytest.approx(0.007)
    assert bravo.lanes == ("L02", "L03")  # the lane that got it wrong, and its fork that solved it
    assert (bravo.tokens, bravo.turns) == (7000, 2) and bravo.dollars == pytest.approx(0.07)
    assert result.tokens == 9300
    assert result.dollars == pytest.approx(0.004 + 0.003 + 0.02 + 0.05 + 0.001)
    assert result.cost_per_solve == pytest.approx(result.dollars / 2)
    assert result.unpriced == () and result.dollars == pytest.approx(result.known_dollars)


def test_the_lanes_in_the_score_agree_with_the_deck_that_ran_them(tmp_path):
    played = Played(tmp_path, all_priced=True).play()
    result = score(played.close(), played.board)
    assert list(result.lanes) == list(played.deck.lanes)
    for lane in played.deck.lanes.values():
        got = result.lanes[lane.id]
        assert (got.challenge, got.turns, got.tokens, got.state) == (lane.challenge_id, lane.turns, lane.tokens, lane.state.value if lane.finished else None)
        assert got.dollars == pytest.approx(lane.dollars)
    assert (result.lanes["L03"].parent, result.lanes["L03"].model) == ("L02", "big")


def test_an_unpriced_lane_makes_its_cost_unknown_and_the_known_part_a_floor(played):
    result = score(played.close(), played.board)
    assert result.unpriced == ("L02",)
    assert result.lanes["L02"].dollars is None and played.deck.lanes["L02"].dollars is None
    assert result.per_challenge["bravo"].dollars is None  # L02 worked bravo
    assert result.per_challenge["alpha"].dollars == pytest.approx(0.007)
    assert result.dollars is None and result.cost_per_solve is None
    assert result.known_dollars == pytest.approx(0.004 + 0.003 + 0.05 + 0.001)
    assert any(note.startswith("L02 had turns with no price") for note in result.notes)


def test_interventions_are_counted_per_challenge_and_refused_ones_are_not(played):
    result = score(played.close(), played.board)
    per = result.per_challenge
    assert (per["alpha"].interventions, per["bravo"].interventions, per["charlie"].interventions) == (1, 4, 1)
    assert per["delta"].interventions == 0
    assert result.interventions == 6  # seven asked for; one approve was refused
    assert dict(result.intervention_kinds) == {"approve": 3, "fork": 1, "hint": 1, "kill": 1}
    assert list(result.intervention_kinds) == ["approve", "fork", "hint", "kill"]  # most first, then by name


def test_a_wrong_submission_is_counted_where_it_was_made(played):
    result = score(played.close(), played.board)
    assert result.wrong_submissions == 1
    assert [result.per_challenge[cid].wrong_submissions for cid in CHALLENGES] == [0, 1, 0, 0]


def test_a_challenge_queue_intervention_counts_for_that_challenge(tmp_path):
    played = Played(tmp_path)
    played.at(0)
    played.at(600)
    played.deck.apply(iv.Kill("L03", requeue=False))  # charlie parked
    played.deck.apply(iv.Queue("charlie"))  # and queued again by the player
    played.deck.apply(iv.Queue("no-such-challenge"))  # refused, and not on the board: neither counts nor breaks the score
    result = score(played.close(), played.board)
    assert result.per_challenge["charlie"].interventions == 2
    assert result.interventions == 2 and result.per_challenge["charlie"].lanes == ("L03", "L04")


def test_scoring_reads_only_the_log_so_a_later_score_is_the_same(played):
    path = played.close()
    first = score(path, played.board)
    played.deck.report("L04", TurnReport(action="too late"))  # the deck moves on; the closed log does not
    copy = path.parent.parent / "copied" / "events.jsonl"
    copy.parent.mkdir()
    copy.write_bytes(path.read_bytes())
    assert score(copy, load_board(played.folder)) == first


def test_the_answers_file_is_the_judge_when_the_board_has_one(tmp_path):
    """Played on a board with no answers (the player confirms each hand submit), then scored
    against the archive's answers: a flag the player wrongly accepted does not count, and a
    right one they rejected does, each with a note."""
    played = Played(tmp_path, answers=None)
    deck = played.at(0).deck
    deck.report("L01", TurnReport(action="guess", flag=WRONG))
    deck.apply(iv.Approve("L01"))  # submit by hand...
    played.at(50)
    deck.apply(iv.Approve("L01"))  # ...and say it was accepted: alpha "solved" with the wrong flag
    deck.report("L02", TurnReport(action="solve", flag=FLAGS["bravo"]))
    deck.apply(iv.Approve("L02"))
    played.at(80)
    deck.apply(iv.Decline("L02"))  # the player says the right flag was rejected
    path = played.close()

    as_run = score(path, played.board)  # the same board, with no answers: the run's verdicts stand
    assert as_run.solved == ("alpha",) and as_run.per_challenge["alpha"].checked == "player"
    assert as_run.per_challenge["bravo"].wrong_submissions == 1

    (played.folder / "answers.sha256.json").write_text(json.dumps({cid: sha(flag) for cid, flag in FLAGS.items()}))
    judged = score(path, load_board(played.folder))
    assert judged.solved == ("bravo",) and judged.points == 200 and judged.first_solve_at == 80.0
    assert judged.per_challenge["bravo"].checked == "answers"
    assert judged.per_challenge["alpha"].wrong_submissions == 1 and judged.wrong_submissions == 1
    assert "The answers file rejects a flag the run took for Alpha Gate, so it is not counted." in judged.notes
    assert "The answers file accepts a flag the run was told was wrong for Bravo Box, so it is counted." in judged.notes


def test_a_verdict_for_a_challenge_the_answers_file_does_not_cover_stands(tmp_path):
    platform = {cid: flag for cid, flag in FLAGS.items() if cid != "alpha"}  # the platform knew alpha's flag

    def verify(cid, flag):
        return flag == FLAGS[cid]

    played = Played(tmp_path, answers=platform, verify=verify)
    deck = played.at(0).deck
    deck.report("L01", TurnReport(action="solve", flag=FLAGS["alpha"]))
    deck.apply(iv.Approve("L01"))
    result = score(played.close(), played.board)
    assert result.solved == ("alpha",) and result.per_challenge["alpha"].checked == "platform"


def test_an_explicit_answers_file_outside_the_board_is_used(tmp_path):
    played = Played(tmp_path, answers=None)
    deck = played.at(0).deck
    deck.report("L01", TurnReport(action="solve", flag=FLAGS["alpha"]))
    deck.apply(iv.Approve("L01"))
    played.at(20)
    deck.apply(iv.Approve("L01"))  # the player confirms it
    path = played.close()
    kept = tmp_path / "kept-apart" / "answers.json"
    kept.parent.mkdir()
    kept.write_text(json.dumps({"alpha": sha(FLAGS["alpha"])}))
    result = score(path, load_board(played.folder, answers=kept))
    assert result.solved == ("alpha",) and result.per_challenge["alpha"].checked == "answers"
    assert result.answers == kept.resolve()


def test_a_teammate_solve_is_recorded_and_earns_us_nothing(tmp_path):
    folder = make_board(tmp_path / "archive")
    board = load_board(folder)
    clock, driver = Clock(), Driver()
    config = DeckConfig(event=board.event, team=True, max_lanes=4, flag_format=FLAG_FORMAT, models=MODELS)
    deck = Deck(config, driver, clock, AnswerVerifier(board.answers))
    log = EventLog(tmp_path / "run" / "events.jsonl")
    log.attach(deck)
    Release(deck, board, load_timeline(board), cheapest_first(board)).tick()
    clock.t = 40.0
    deck.teammate_solved("charlie", "wren")
    log.close()
    result = score(log.path, board)
    assert result.solved == () and result.points == 0
    assert result.per_challenge["charlie"].teammate == "wren"
    assert result.lanes[result.per_challenge["charlie"].lanes[0]].state == "stopped"


# ---------------------------------------------------------------------- logs that are odd or wrong


def lines_of(path: Path) -> list[str]:
    return path.read_text(encoding="ascii").splitlines(keepends=True)


def test_a_log_cut_off_mid_line_is_scored_with_a_note(played):
    path = played.close()
    whole = score(path, played.board)
    body = lines_of(path)
    assert json.loads(body[-1])["kind"] == "run-end"
    cut = path.parent / "cut.jsonl"
    cut.write_text("".join(body[:-1]) + body[-1][:25], encoding="ascii")  # the run-end line, half written
    result = score(cut, played.board)
    assert "The log's last line was cut off (the run did not close cleanly); it is left out." in result.notes
    assert "The log has no run-end line: the run is still going, or it did not close cleanly." in result.notes
    assert (result.solved, result.points, result.tokens, result.interventions) == (
        whole.solved, whole.points, whole.tokens, whole.interventions,
    )


def test_an_intervention_whose_outcome_never_came_still_counts(played):
    path = played.close()
    body = lines_of(path)
    last_outcome = max(i for i, line in enumerate(body) if json.loads(line)["kind"] == "outcome")
    crashed = path.parent / "crashed.jsonl"
    crashed.write_text("".join(body[:last_outcome]), encoding="ascii")  # the last approve, with no outcome or end
    result = score(crashed, played.board)
    assert result.interventions == 6
    assert "The log has no run-end line: the run is still going, or it did not close cleanly." in result.notes


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        ("", "is empty, not an event log"),
        ("\n\n", "is empty, not an event log"),
        ('{"kind": "turn", "at": 1}\n', "does not start with a run-start line"),
        ("just some text\n", "line 1 is not JSON"),
        ('{"kind": "run-start"}\n[1, 2]\n', "line 2 is not a flightdeck event"),
        ('{"kind": "run-start"}\n{"at": 1}\n', "line 2 is not a flightdeck event"),
        ('{"kind": "run-start"}\nnot json\n{"kind": "run-end"}\n', "line 2 is not JSON"),
        ('{"kind": "run-start"}\n{"kind": "run-end"}\n{"kind": "run-start"}\n{"kind": "run-end"}\n', "holds 2 runs"),
        ('{"kind": "run-start"}\n{"kind": "turn", "lane": "L01", "challenge": "alpha", "data": {"tokens": 1}}\n', 'line 2: the turn event has no at'),
        ('{"kind": "run-start"}\n{"kind": "turn", "at": -3, "lane": "L01", "challenge": "alpha", "data": {"tokens": 1, "dollars": 0}}\n', "line 2: the turn event's at must be a time"),
        ('{"kind": "run-start"}\n{"kind": "turn", "at": 1, "lane": "L01", "challenge": "alpha", "data": {"tokens": "lots", "dollars": 0}}\n', "line 2: the turn event's data.tokens must be a token count"),
        ('{"kind": "run-start"}\n{"kind": "turn", "at": 1, "lane": "L01", "challenge": "alpha", "data": {"tokens": 5}}\n', "line 2: the turn event has no data.dollars"),
        ('{"kind": "run-start"}\n{"kind": "turn", "at": 1, "lane": "L01", "challenge": "alpha", "data": {"tokens": 5, "dollars": "nan"}}\n', "data.dollars must be a dollar amount"),
        ('{"kind": "run-start"}\n{"kind": "submit", "at": 1, "lane": "L01", "challenge": "alpha", "data": {"flag": "t{x}", "correct": "yes"}}\n', "data.correct must be correct: true or false"),
        ('{"kind": "run-start"}\n{"kind": "release", "at": 1, "data": "alpha"}\n', "the release event's data must be an object"),
        ('{"kind": "run-start"}\n{"kind": "outcome", "at": 1, "lane": "L01", "data": {"intervention": "hint", "ok": true}}\n', 'an outcome of "hint" with no intervention before it'),
    ],
)
def test_a_log_that_is_not_a_sound_event_log_is_an_error_naming_the_line(tmp_path, content, problem):
    board = load_board(make_board(tmp_path / "archive"))
    path = tmp_path / "events.jsonl"
    path.write_text(content, encoding="ascii")
    with pytest.raises(ScoreError) as caught:
        score(path, board)
    message = str(caught.value)
    assert message.startswith(f"{path}:") and problem in message, message


def test_a_solve_the_log_gives_no_lane_is_the_players_own(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    path = tmp_path / "events.jsonl"
    events = [
        {"kind": "run-start"},
        {"kind": "release", "at": 0, "data": {"challenges": list(CHALLENGES)}},
        {"kind": "submit", "at": 75.5, "lane": None, "challenge": "alpha", "data": {"flag": FLAGS["alpha"], "correct": True, "by": "player"}},
        {"kind": "run-end"},
    ]
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="ascii")
    result = score(path, board)
    assert result.solved == ("alpha",) and result.per_challenge["alpha"].solved_by == ME
    assert result.per_challenge["alpha"].checked == "answers" and result.first_solve_at == 75.5
    assert "solved by you" in scorecard(result)


def test_a_log_from_another_board_is_an_error_naming_the_strangers(played):
    path = played.close()
    other = load_board(
        make_board(played.folder.parent / "other", {"alpha": ("Alpha Gate", "crypto", 50), "echo": ("Echo", "misc", 10)}, answers=None)
    )
    with pytest.raises(ScoreError) as caught:
        score(path, other)
    message = str(caught.value)
    assert 'not on the board "Sample Archive": "bravo", "charlie"' in message
    assert "--board" in message


def test_a_log_that_is_missing_a_directory_or_binary_is_an_error(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    with pytest.raises(ScoreError, match="no such file"):
        score(tmp_path / "none.jsonl", board)
    with pytest.raises(ScoreError, match="is a directory"):
        score(tmp_path, board)
    binary = tmp_path / "events.jsonl"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")
    with pytest.raises(ScoreError, match="is not text"):
        score(binary, board)


NASTY = "zulu\x1b]0;owned\x07\x1b[2J\nforged: solved 99 of 99"  # sets the window title, clears the screen, forges a line
HOSTILE_EVENTS = {
    "an id": {"kind": "release", "at": 0, "data": {"challenges": [NASTY]}},
    "a kind, with no at": {"kind": NASTY},
    "a kind, with a bad at": {"kind": NASTY, "at": -1},
    "a kind, with bad data": {"kind": NASTY, "at": 1, "data": "x"},
}


def hostile_log(folder: Path, case: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "events.jsonl"
    path.write_text('{"kind": "run-start"}\n' + json.dumps(HOSTILE_EVENTS[case]) + "\n", encoding="ascii")
    return path


@pytest.mark.parametrize("case", list(HOSTILE_EVENTS))
def test_untrusted_text_in_a_log_error_cannot_reach_the_terminal_raw(tmp_path, case):
    board = load_board(make_board(tmp_path / "archive"))
    path = hostile_log(tmp_path / "run", case)
    with pytest.raises(ScoreError) as caught:
        score(path, board)
    message = str(caught.value)
    assert "\x1b" not in message and "\x07" not in message and "\n" not in message
    assert message.startswith(f"{path}: ") and "zulu^[]0;owned^G^[[2J ⏎ forged" in message


def test_a_kind_flightdeck_writes_is_named_plainly_in_an_error(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    path = tmp_path / "events.jsonl"
    path.write_text('{"kind": "run-start"}\n{"kind": "lane.start", "at": 1}\n', encoding="ascii")
    with pytest.raises(ScoreError, match=r"line 2: the lane\.start event has no lane \(a lane id\)$"):
        score(path, board)
    path.write_text('{"kind": "run-start"}\n{"kind": "lane.starts", "at": 1, "data": []}\n', encoding="ascii")
    with pytest.raises(ScoreError, match=r'line 2: the "lane\.starts" event\'s data must be an object$'):
        score(path, board)


# ---------------------------------------------------------------------- the scorecard


def test_the_scorecard_shows_the_totals_and_one_row_per_challenge(played):
    card = scorecard(score(played.close(), played.board))
    lines = card.splitlines()
    assert lines[0] == "Sample Archive: solved 2 of 4 · 250 of 650 points"
    assert "Released 3 of 4: 1 never reached the board in this run" in lines
    assert "First solve T+00:02:10 · last event T+00:15:00" in lines
    assert "Spent 9k tokens · $0.06+ · $0.03+ per solve" in lines
    assert "Interventions 6 (approve 3, fork 1, hint 1, kill 1) · wrong submissions 1" in lines
    assert "Flags checked against answers.sha256.json" in lines
    header = next(i for i, line in enumerate(lines) if line.startswith("challenge "))
    rows = lines[header + 1 : header + 5]
    assert [row.split("  ")[0] for row in rows] == ["Alpha Gate", "Bravo Box", "Charlie Chart", "Delta Drift"]
    alpha, bravo, charlie, delta = (row.split() for row in rows)
    assert alpha[2:] == ["cry", "50", "solved", "L01", "T+00:02:10", "2m", "1", "2k", "$0.01", "1"]
    assert bravo[2:] == ["web", "200", "solved", "L03", "T+00:15:00", "15m", "2", "7k", "-", "4", "1"]
    assert charlie[2:] == ["misc", "100", "tried", "(killed)", "1", "300", "$0.00", "1"]
    assert delta[2:] == ["rev", "300", "not", "released"]
    assert lines[header + 5] == "took: release to solve · iv: your interventions · wrong: wrong flags submitted"
    assert "- L02 had turns with no price, so its cost is not fully known: the dollars count only priced turns." in lines


def test_the_scorecard_columns_line_up(played):
    lines = scorecard(score(played.close(), played.board)).splitlines()
    header = next(i for i, line in enumerate(lines) if line.startswith("challenge "))
    table = lines[header : header + 5]
    result_at = table[0].index("result")  # a text column: every cell starts under its header
    assert [row[result_at:].split("  ")[0] for row in table[1:]] == ["solved L01", "solved L03", "tried (killed)", "not released"]
    assert {row[result_at - 1] for row in table[1:]} == {" "}
    tokens_end = table[0].index("tokens") + len("tokens")  # a number column: every cell ends under its header's end
    for row, value in zip(table[1:4], ["2k", "7k", "300"]):
        assert row[tokens_end - len(value) : tokens_end] == value and row[tokens_end - len(value) - 1] == " ", row
        assert row[tokens_end] == " ", row


SEVEN = {
    **CHALLENGES,
    "echo": ("Echo Engine", "pwn", 400),
    "foxtrot": ("Foxtrot Fax", "misc", 150),
    "golf": ("Golf Gopher", "misc", 250),
}


def table(card: str) -> list[list[str]]:
    """The scorecard's table rows (below its header, above the key) as cells."""
    lines = card.splitlines()
    header = next(i for i, line in enumerate(lines) if line.startswith("challenge "))
    end = lines.index("took: release to solve · iv: your interventions · wrong: wrong flags submitted")
    return [re.split(r"\s{2,}", line.strip()) for line in lines[header + 1 : end]]


def test_the_scorecard_rows_go_solved_in_solve_order_then_teammate_tried_released_and_never_released(tmp_path):
    folder = make_board(tmp_path / "archive", SEVEN, timeline={"waves": [{"at": 99_999, "ids": ["foxtrot"]}]})
    board = load_board(folder)
    clock, driver = Clock(), Driver()
    config = DeckConfig(event=board.event, team=True, max_lanes=6, flag_format=FLAG_FORMAT, models=MODELS)
    deck = Deck(config, driver, clock, AnswerVerifier(board.answers))
    log = EventLog(tmp_path / "run" / "events.jsonl")
    log.attach(deck)
    every_but_echo = lambda ids: [QueueEntry(cid, MODELS[0]) for cid in ids if cid != "echo"]  # noqa: E731
    Release(deck, board, load_timeline(board), every_but_echo).tick()
    assert [lane.challenge_id for lane in deck.lanes.values()] == ["alpha", "bravo", "charlie", "delta", "golf"]
    clock.t = 100.0
    deck.report("L02", TurnReport(action="solve", tokens=100, flag=FLAGS["bravo"]))
    deck.apply(iv.Approve("L02"))  # bravo, later on the board than alpha, is solved first
    clock.t = 150.0
    deck.report("L03", TurnReport(action="strings chart.bin", tokens=300))
    deck.report("L04", TurnReport(action="objdump -d drift", tokens=5000))
    clock.t = 200.0
    deck.report("L01", TurnReport(action="solve", tokens=100, flag=FLAGS["alpha"]))
    deck.apply(iv.Approve("L01"))
    clock.t = 250.0
    deck.teammate_solved("golf", "wren")
    log.close()

    result = score(log.path, board)
    assert result.solved == ("bravo", "alpha") and result.first_solve_at == 100.0
    assert [(cells[0], cells[3]) for cells in table(scorecard(result))] == [
        ("Bravo Box", "solved L02"),
        ("Alpha Gate", "solved L01"),
        ("Golf Gopher", "teammate wren"),
        ("Delta Drift", "tried (open)"),  # tried: most tokens first, and still open when the log ends
        ("Charlie Chart", "tried (open)"),
        ("Echo Engine", "not tried"),
        ("Foxtrot Fax", "not released"),
    ]


def test_solves_at_the_same_time_keep_the_order_of_the_log(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    clock, driver = Clock(), Driver()
    config = DeckConfig(event=board.event, max_lanes=4, flag_format=FLAG_FORMAT, models=MODELS, submit="auto")
    deck = Deck(config, driver, clock, AnswerVerifier(board.answers))
    log = EventLog(tmp_path / "run" / "events.jsonl")
    log.attach(deck)
    Release(deck, board, load_timeline(board), cheapest_first(board)).tick()  # alpha L01, charlie L02, bravo L03, delta L04
    clock.t = 50.0
    deck.report("L03", TurnReport(action="solve", flag=FLAGS["bravo"]))  # submitted at once: bravo first in the log
    deck.report("L01", TurnReport(action="solve", flag=FLAGS["alpha"]))  # then alpha, at the same deck time
    log.close()
    records = [json.loads(line) for line in lines_of(log.path)]
    assert [(r["challenge"], r["at"]) for r in records if r["kind"] == "submit"] == [("bravo", 50.0), ("alpha", 50.0)]
    result = score(log.path, board)
    assert result.solved == ("bravo", "alpha") and result.first_solve_at == 50.0
    assert [cells[0] for cells in table(scorecard(result))][:2] == ["Bravo Box", "Alpha Gate"]


def test_the_scorecard_never_shows_a_flag(played):
    card = scorecard(score(played.close(), played.board))
    for flag in [*FLAGS.values(), WRONG]:
        assert flag not in card
    assert "{" not in card


def test_names_in_the_scorecard_cannot_forge_a_line_or_reach_the_terminal(tmp_path):
    challenges = {
        "alpha": ("Alpha\nSample Archive: solved 4 of 4 · 650 of 650 points", "crypto", 50),
        "bravo": ("Bravo\x1b[2J\x1b[31m", "web‮", 200),
    }
    board = load_board(make_board(tmp_path / "archive", challenges, answers={"alpha": FLAGS["alpha"], "bravo": FLAGS["bravo"]}))
    deck, _, _ = make_deck(board)
    log = EventLog(tmp_path / "run" / "events.jsonl")
    log.attach(deck)
    Release(deck, board, load_timeline(board), cheapest_first(board)).tick()
    log.close()
    card = scorecard(score(log.path, board))
    assert "\x1b" not in card and "‮" not in card
    assert card.splitlines()[0] == "Sample Archive: solved 0 of 2 · 0 of 250 points"
    assert sum(line.startswith("Sample Archive:") for line in card.splitlines()) == 1
    assert "Alpha ⏎ Sample Archive:…" in card and "Bravo^[[2J^[[31m" in card  # folded, then cut at 24 cells


def test_a_run_with_no_solve_says_so(tmp_path):
    board = load_board(make_board(tmp_path / "archive"))
    deck, _, _ = make_deck(board)
    log = EventLog(tmp_path / "run" / "events.jsonl")
    log.attach(deck)
    log.close()
    card = scorecard(score(log.path, board))
    assert card.splitlines()[:3] == [
        "Sample Archive: solved 0 of 4 · 0 of 650 points",
        "Released 0 of 4: 4 never reached the board in this run",
        "No solve",
    ]
    assert "Spent 0 tokens · $0.00" in card and "per solve" not in card


def test_solves_not_checked_against_an_answers_file_are_marked(tmp_path):
    played = Played(tmp_path, answers=None)
    deck = played.at(0).deck
    deck.report("L01", TurnReport(action="solve", flag=FLAGS["alpha"]))
    deck.apply(iv.Approve("L01"))
    deck.apply(iv.Approve("L01"))  # the player says the platform accepted it
    card = scorecard(score(played.close(), played.board))
    assert "No answers file: solves are as the run recorded them" in card
    assert "solved L01 **" in card
    assert "** not checked against an answers file: you said the platform accepted it" in card


# ---------------------------------------------------------------------- flightdeck score


runner = CliRunner()


def flightdeck() -> typer.Typer:
    """A command line with the practice app mounted the way cli.py mounts it."""
    root = typer.Typer(no_args_is_help=True, add_completion=False, rich_markup_mode="markdown")

    @root.callback()
    def main() -> None:
        """flightdeck"""

    root.add_typer(practice_cli.app)
    return root


def invoke(*args: str):
    return runner.invoke(flightdeck(), list(args), prog_name="flightdeck")


def test_score_prints_the_scorecard_of_a_run_folder(played):
    path = played.close()
    result = invoke("score", str(path.parent), "--board", str(played.folder))
    assert result.exit_code == 0, result.stderr
    assert result.stdout == scorecard(score(path, played.board))
    assert result.stdout.startswith("Sample Archive: solved 2 of 4 · 250 of 650 points\n")


def test_score_takes_the_event_log_itself_too(played):
    path = played.close()
    result = invoke("score", str(path), "--board", str(played.folder))
    assert result.exit_code == 0 and result.stdout == scorecard(score(path, played.board))


def test_score_checks_flags_against_a_named_answers_file(tmp_path):
    played = Played(tmp_path, answers=None)
    deck = played.at(0).deck
    deck.report("L01", TurnReport(action="guess", flag=WRONG))
    deck.apply(iv.Approve("L01"))
    deck.apply(iv.Approve("L01"))  # wrongly accepted by the player
    path = played.close()
    kept = tmp_path / "answers-kept-apart.json"
    kept.write_text(json.dumps({"alpha": sha(FLAGS["alpha"])}))
    plain = invoke("score", str(path.parent), "--board", str(played.folder))
    judged = invoke("score", str(path.parent), "--board", str(played.folder), "--answers", str(kept))
    assert plain.stdout.startswith("Sample Archive: solved 1 of 4")
    assert judged.exit_code == 0 and judged.stdout.startswith("Sample Archive: solved 0 of 4")
    assert "Flags checked against answers-kept-apart.json" in judged.stdout


def test_score_defaults_to_the_practice_set(played, monkeypatch):
    path = played.close()
    monkeypatch.setattr(practice_set, "practice_dir", lambda: played.folder)
    result = invoke("score", str(path.parent))
    assert result.exit_code == 0 and result.stdout == scorecard(score(path, played.board))


def test_score_without_a_practice_set_says_to_name_the_board(played, monkeypatch):
    path = played.close()

    def missing():
        raise FileNotFoundError("the practice set is missing from this installation (looked in /x)")

    monkeypatch.setattr(practice_set, "practice_dir", missing)
    result = invoke("score", str(path.parent))
    assert result.exit_code == 2 and result.stdout == ""
    assert "flightdeck: the practice set is missing from this installation (looked in /x); name the board the run played with --board" in result.stderr


@pytest.mark.parametrize("make", ["empty folder", "nothing there"])
def test_score_of_something_that_is_not_a_run_says_so(tmp_path, make):
    board = make_board(tmp_path / "archive")
    target = tmp_path / "target"
    if make == "empty folder":
        target.mkdir()
    result = invoke("score", str(target), "--board", str(board))
    assert result.exit_code == 2 and result.stdout == ""
    expected = "no events.jsonl here, so it is not a run folder" if make == "empty folder" else "no such run folder or event log"
    assert f"flightdeck: {target}: {expected}" in result.stderr


def test_score_against_the_wrong_board_fails_with_the_reason(played):
    path = played.close()
    other = make_board(played.folder.parent / "other", {"echo": ("Echo", "misc", 10)}, answers=None)
    result = invoke("score", str(path.parent), "--board", str(other))
    assert result.exit_code == 2 and result.stdout == ""
    assert "the run played challenges that are not on the board" in result.stderr


def test_score_with_a_board_that_does_not_load_fails_with_the_reason(played, tmp_path):
    path = played.close()
    result = invoke("score", str(path.parent), "--board", str(tmp_path / "no-board-here"))
    assert result.exit_code == 2 and "no such directory" in result.stderr


@pytest.mark.parametrize("case", list(HOSTILE_EVENTS))
def test_score_of_a_hostile_log_prints_its_reason_as_one_safe_line(tmp_path, case):
    board = make_board(tmp_path / "archive")
    log = hostile_log(tmp_path / "run", case)
    result = invoke("score", str(log.parent), "--board", str(board))
    assert result.exit_code == 2 and result.stdout == ""
    assert "\x1b" not in result.stderr and "\x07" not in result.stderr and result.stderr.count("\n") == 1
    assert result.stderr.startswith(f"flightdeck: {log}: ") and "zulu^[]0;owned^G^[[2J ⏎ forged" in result.stderr


def test_score_folds_a_reason_whoever_wrote_it(played, monkeypatch):
    path = played.close()

    def missing():
        raise FileNotFoundError(f"the practice set is missing from this installation (looked in /x/{NASTY})")

    monkeypatch.setattr(practice_set, "practice_dir", missing)
    result = invoke("score", str(path.parent))
    assert result.exit_code == 2 and result.stdout == ""
    assert "\x1b" not in result.stderr and "\x07" not in result.stderr and result.stderr.count("\n") == 1
    assert "(looked in /x/zulu^[]0;owned^G^[[2J ⏎ forged: solved 99 of 99); name the board" in result.stderr


def test_score_is_listed_in_the_help_with_its_arguments():
    listed = invoke("--help")
    assert listed.exit_code == 0 and "score" in listed.stdout
    usage = invoke("score", "--help")
    assert usage.exit_code == 0
    text = " ".join(usage.stdout.split())
    assert "RUN_DIR" in text and "--board" in text and "--answers" in text and "practice set" in text

