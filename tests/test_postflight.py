"""The post-flight report, read from run folders that a real deck, event log and transcript
log wrote.

A recording driver stands in for lane work: it notes what the deck asked of it and does no
work. A manual clock moves time and the verifier knows each challenge's flag. L1 results
are logged as a lane's L1 stage logs them (agent/driver.py): Deck.record_l1 on the lane,
then each flag of a "solved" or "candidate" result reported on that lane, so it waits for
the player's approval like any other. What a Markdown renderer makes of the report is
checked with a CommonMark parser (markdown-it, which the console already depends on).
"""

from __future__ import annotations

import itertools
import json
import os
import re
from pathlib import Path

import pytest
import typer
from markdown_it import MarkdownIt
from typer.testing import CliRunner

from ctf_flightdeck import cli, writeup
from ctf_flightdeck.agent.l1stage import FLAG_STATUSES
from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import ME, Alert, AlertKind, Challenge, DeckConfig
from ctf_flightdeck.eventlog import EventLog
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.postflight import md_code, md_fence, md_text, report, solves, summary
from ctf_flightdeck.practice_mode import score, scorecard
from ctf_flightdeck.runrecord import load_run
from ctf_flightdeck.text import untrusted
from ctf_flightdeck.transcript import TranscriptLog

FLAG_FORMAT = r"t\{[^{}]+\}"
MODELS = ("small", "big")


class RecordingDriver:
    """Notes what the deck asked of it and does no work. A challenge id in `fail` makes
    start() raise with that message."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.fail: dict[str, str] = {}

    def attach(self, deck):
        self.deck = deck

    def start(self, lane, challenge):
        if challenge.id in self.fail:
            raise RuntimeError(self.fail[challenge.id])
        self.calls.append(("start", lane.id, challenge.id))

    def pause(self, lane):
        self.calls.append(("pause", lane.id))

    def resume(self, lane):
        self.calls.append(("resume", lane.id))

    def hint(self, lane, text):
        self.calls.append(("hint", lane.id, text))

    def redirect(self, lane, text):
        self.calls.append(("redirect", lane.id, text))

    def escalate(self, lane, model, summary):
        self.calls.append(("escalate", lane.id, model))

    def approved(self, lane, pending):
        self.calls.append(("approved", lane.id, pending.kind))

    def rejected(self, lane, flag):
        self.calls.append(("rejected", lane.id, flag))

    def declined(self, lane, pending):
        self.calls.append(("declined", lane.id, pending.kind))

    def stop(self, lane):
        self.calls.append(("stop", lane.id))


class Script:
    """A run played by script; the real deck, EventLog and TranscriptLog write its folder."""

    def __init__(self, folder: Path, *, flags=None, models=MODELS, team=True, max_lanes=8, clock=None, event="test") -> None:
        self.folder = folder
        self.clock = clock if clock is not None else ManualClock(0.0)
        self.driver = RecordingDriver()
        self.flags = dict(flags or {})
        self.models = models
        config = DeckConfig(event=event, team=team, max_lanes=max_lanes, flag_format=FLAG_FORMAT, models=models)
        self.deck = Deck(config, self.driver, self.clock, lambda cid, flag: self.flags.get(cid) == flag)
        self.log = EventLog(folder / "events.jsonl")
        self.log.attach(self.deck)
        self.transcripts = TranscriptLog(folder / "lanes")
        self.transcripts.attach(self.deck)

    def at(self, seconds: float) -> None:
        assert seconds >= self.clock.now(), "a script runs forward in time"
        self.clock.advance(seconds - self.clock.now())

    def release(self, challenges, queue=None, label="Board", **entry) -> None:
        queue = [c.id for c in challenges] if queue is None else queue
        self.deck.release(challenges, [QueueEntry(cid, self.models[0], **entry) for cid in queue], label)

    def lane(self, cid: str) -> str:
        (lane,) = self.deck.lanes_on(cid)
        return lane.id

    def newest(self) -> str:
        return max(self.deck.lanes.values(), key=lambda lane: lane.number).id

    def turn(self, lane: str, action: str = "step", *, tokens=1000, cached=250, dollars=0.01, **more) -> None:
        self.deck.report(lane, TurnReport(action=action, tokens=tokens, cached_tokens=cached, dollars=dollars, **more))

    def do(self, intervention):
        return self.deck.apply(intervention)

    def l1(self, cid: str, engine: str, status: str, flags=(), *, lane: str, seconds=0.5, notes="") -> None:
        """An L1 engine's result on a lane, as the lane's L1 stage logs it: the deck records
        it, and a flag it found becomes the lane's candidate (no turn), for the player to approve."""
        self.deck.record_l1(cid, engine, status, flags=flags, seconds=seconds, notes=notes, lane_id=lane)
        if status in FLAG_STATUSES:
            for flag in flags:
                self.deck.report(lane, TurnReport(turn=False, flag=flag))

    def close(self):
        self.transcripts.close()
        self.log.close()
        return load_run(self.folder)


BOARD = [  # id, name, category, points
    ("alpha", "Alpha", "misc", 50),
    ("bravo", "Bravo", "web", 100),
    ("charlie", "Charlie", "crypto", 200),
    ("delta", "Delta", "rev", 300),
    ("echo", "Echo", "pwn", 150),
    ("foxtrot", "Foxtrot", "forensics", 100),
    ("golf", "Golf", "misc", 50),
    ("hotel", "Hotel", "web", 200),
    ("india", "India", "web", 100),
]
FLAGS = {"alpha": "t{alpha}", "bravo": "t{bravo}", "charlie": "t{charlie}", "delta": "t{delta}", "hotel": "t{hotel}"}


def write_board(folder: Path) -> Path:
    folder.mkdir()
    (folder / "board.json").write_text(json.dumps({"event": "Test CTF", "flag_format": FLAG_FORMAT}))
    for cid, name, category, points in BOARD:
        (folder / cid).mkdir()
        (folder / cid / "challenge.json").write_text(json.dumps({"name": name, "category": category, "points": points}))
    return folder


def play(tmp_path: Path):
    """The whole board, played by script (times in deck seconds). Every turn is 1,000 tokens
    and $0.01 on small, 2,000 tokens and $0.05 on big (hotel's two: $0.02), a quarter cached.

    alpha    L1 strings finds nothing on L01; L01 loops (turn 2, 20), a hint at 50, solved at 70: helped.
    bravo    L1 sqli finds the flag on L08, which you approve at 5: solved by L1 (L08 took no turn).
    charlie  L02 stalls (turn 1, 30); escalated at 500; solved 12 turns later at 1710: no effect seen.
    delta    L03 overthinks (turn 5, 105); forked at 200 to L09 on big, solved 3 turns later
             at 240: helped. L03 stops.
    echo     L04 gives up at 310.          foxtrot  L05 is killed and parked at 330.
    golf     teammate wren solves it at 350; L06 stops.
    hotel    L07's flag is wrong (410); redirected at 420, no solve; still open at the end.
    india    never queued; teammate wren claims it at 360.
    At 440 a hint to the finished L01 is refused.
    """
    board = load_board(write_board(tmp_path / "board"))
    run = Script(tmp_path / "run", flags=FLAGS)
    queue = ["alpha", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "bravo"]
    run.release([b.challenge for b in board.challenges], queue)
    alpha, charlie, delta, echo, foxtrot, golf, hotel, bravo = (run.lane(cid) for cid in queue)
    run.l1("alpha", "strings", "none", lane=alpha, seconds=0.3, notes="no printable flag")
    run.l1("bravo", "sqli", "solved", ["t{bravo}"], lane=bravo, seconds=1.2)
    run.at(5)
    run.do(iv.Approve(bravo))  # L1's flag, approved on its lane: correct
    run.at(10)
    run.turn(alpha, "cat note")
    run.at(20)
    run.turn(alpha, "cat note", alerts=(Alert(AlertKind.LOOP, "the same command twice: cat note"),))
    run.at(30)
    run.turn(charlie, "python rsa.py", alerts=(Alert(AlertKind.STALL, "no new idea in 3 turns"),))
    run.at(50)
    run.do(iv.Hint(alpha, "decode the base64"))
    run.at(60)
    run.turn(alpha, "base64 -d note", flag="t{alpha}")
    run.at(70)
    run.do(iv.Approve(alpha))
    for turn in range(1, 6):
        run.at(100 + turn)
        effort = (Alert(AlertKind.EFFORT, "5 turns of ghidra on a 300-pointer"),) if turn == 5 else ()
        run.turn(delta, f"ghidra pass {turn}", alerts=effort)
    run.at(200)
    run.do(iv.Fork(delta, "angr it"))
    fork = run.newest()
    for turn in range(1, 4):
        run.at(200 + 10 * turn)
        run.turn(fork, f"angr run {turn}", tokens=2000, cached=500, dollars=0.05, flag="t{delta}" if turn == 3 else None)
    run.at(240)
    run.do(iv.Approve(fork))
    run.at(300)
    run.turn(echo, "checksec ./vuln")
    run.at(310)
    run.turn(echo, "ropper", gave_up="no leak found")
    run.at(320)
    run.turn(foxtrot, "binwalk image.png")
    run.at(330)
    run.do(iv.Kill(foxtrot, requeue=False))
    run.at(340)
    run.turn(golf, "file data")
    run.at(350)
    run.deck.teammate_solved("golf", "wren")
    run.at(360)
    run.deck.teammate_claim("india", "wren")
    run.at(400)
    run.turn(hotel, "curl /", dollars=0.02, flag="t{nope}")
    run.at(410)
    run.do(iv.Approve(hotel))
    run.at(420)
    run.do(iv.Redirect(hotel, "read the source first"))
    run.at(430)
    run.turn(hotel, "cat app.py", dollars=0.02)
    run.at(440)
    assert not run.do(iv.Hint(alpha, "too late")).ok
    run.at(500)
    run.do(iv.Escalate(charlie))
    for turn in range(1, 13):
        run.at(500 + 100 * turn)
        run.turn(charlie, f"sage try {turn}", tokens=2000, cached=500, dollars=0.05, flag="t{charlie}" if turn == 12 else None)
    run.at(1710)
    run.do(iv.Approve(charlie))
    return board, run.close()


@pytest.fixture
def played(tmp_path):
    return play(tmp_path)


# ---------------------------------------------------------------------- reading the Markdown back


def sections(text: str, level: str = "## ") -> dict[str, list[str]]:
    """The report's sections at one heading level: title -> its non-blank lines."""
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith(level):
            current = line[len(level):]
            out[current] = []
        elif current is not None and line.strip():
            if line.startswith("#") and len(line) - len(line.lstrip("#")) < len(level) - 1:
                current = None  # a higher heading ends the section
                continue
            out[current].append(line)
    return out


def items(lines: list[str]) -> list[str]:
    return [line[2:] for line in lines if line.startswith("- ")]


def entries(lines: list[str]) -> list[str]:
    """Timeline entries without the "T+... · " clock."""
    return [re.sub(r"^T\+\d\d:\d\d:\d\d \u00b7 ", "", item) for item in items(lines)]


PARSER = MarkdownIt("commonmark").enable(["table", "strikethrough"])
LINKIFY = MarkdownIt("gfm-like")
FORBIDDEN = {
    "html_block", "html_inline", "image", "link_open", "em_open", "strong_open", "s_open",
    "blockquote_open", "hr", "ordered_list_open", "code_block",
}


def walk(text: str, parser: MarkdownIt = PARSER):
    for token in parser.parse(text):
        yield token
        yield from token.children or ()


def shown(inline) -> str:
    """What a renderer shows for an inline token: its text and code spans, joined."""
    return "".join(child.content for child in inline.children if child.type in ("text", "code_inline"))


def headings(text: str, tag: str) -> list[str]:
    tokens = PARSER.parse(text)
    return [shown(tokens[i + 1]) for i, t in enumerate(tokens) if t.type == "heading_open" and t.tag == tag]


def table_rows(text: str) -> list[list[str]]:
    """Every table row's cells, as a renderer shows them."""
    rows, row = [], None
    for token in PARSER.parse(text):
        if token.type == "tr_open":
            row = []
        elif token.type == "inline" and row is not None:
            row.append(shown(token))
        elif token.type == "tr_close":
            rows.append(row)
            row = None
    return rows


def fold(text: str) -> str:
    return untrusted(text, one_line=True).strip()


# ---------------------------------------------------------------------- the run at a glance


def test_at_a_glance_counts_the_run_with_the_boards_names_and_points(played):
    board, record = played
    glance = items(sections(report(record, board=board))["At a glance"])
    assert glance[0] == "Event: Test CTF (from the board)"
    assert glance[1].startswith(f"Run: run, started {md_text(record.started)}, ended {md_text(record.ended)}")
    assert glance[2:] == [
        "Duration: 28m (first to last event)",
        "Challenges: 9 on the board, 5 solved, 4 not solved",
        "Solves: 5 (lanes 3, L1 1, teammates 1, you 0)",  # bravo is L1's: its flag, accepted on L08
        "Points: 700 of 1250",
        "L1: 2 engine runs",
        "Lanes: 9, 30 turns",
        "Tokens: 45k (45,000), 25% cached",
        "Dollars: $0.92",
        "Cost per solve: $0.31 per lane solve ($0.92 over 3 lane solves)",
    ]


def test_without_the_board_the_run_log_names_the_event_and_every_challenge(played):
    _, record = played
    text = report(record)
    glance = items(sections(text)["At a glance"])
    assert glance[0] == "Event: test (from the run log)"  # the deck's event, as its releases recorded it
    assert "Points: 700 of 1250" in glance  # India had no lane and no transcript: its release named it
    assert "### India (web, 100 pts): not solved" in text.splitlines()
    assert "Problems reading the run" not in sections(text)
    assert text.startswith("# Post-flight: test\n")
    assert summary(record).splitlines()[0] == "Post-flight: test, run run"


def test_an_older_log_without_the_board_says_what_it_lacks_never_guesses(played):
    _, record = played
    record = load_run(older(record.dir))
    text = report(record)
    glance = items(sections(text)["At a glance"])
    assert glance[0] == "Event: not in the run log (give --board to name it)"
    assert "Points: 700 of at least 1150 (1 challenge with no known points)" in glance  # every solve had a lane
    assert "### india (category unknown, points unknown): not solved" in text.splitlines()  # no lane, no transcript
    assert "- no name or points in the run for india (give --board to fill them in)" in text.splitlines()
    assert "### Bravo (web, 100 pts): solved by L1 engine sqli" in text.splitlines()  # from L08's transcript
    assert text.startswith("# Post-flight: run run\n")
    assert summary(record).splitlines()[0] == "Post-flight: event not in the run log, run run"


def test_solves_are_credited_to_whoever_got_there_first(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}", "y": "t{y}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20), Challenge("z", "Z", "misc", 30)])
    run.l1("y", "guess", "solved", ["t{wrong}"], lane=run.lane("y"))
    run.do(iv.Approve(run.lane("y")))  # L1's flag is submitted and rejected: L02 carries on
    run.at(5)
    run.deck.teammate_solved("z", ME)  # the player said they solved it themself
    run.turn(run.lane("x"), "solve", flag="t{x}")
    run.do(iv.Approve(run.lane("x")))
    run.at(9)
    run.turn(run.lane("y"), "solve", flag="t{y}")
    run.do(iv.Approve(run.lane("y")))
    record = run.close()
    found = solves(record)
    assert {cid: (s.by, s.who, s.at) for cid, s in found.items()} == {
        "z": ("player", ME, 5.0), "x": ("lane", "L01", 5.0), "y": ("lane", "L02", 9.0),
    }
    assert "- Solves: 3 (lanes 2, L1 0, teammates 0, you 1)" in report(record).splitlines()


def test_a_solve_the_platform_lists_is_yours_or_your_teams_never_a_teammates(tmp_path):
    run = Script(tmp_path, flags={"z": "t{z}"}, team=False)
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20), Challenge("z", "Z", "misc", 30)])
    x, y, z = run.lane("x"), run.lane("y"), run.lane("z")
    run.deck.platform_solved("x", "you", before_run=True)  # solved by hand before this run started
    run.at(30)
    run.deck.platform_solved("y", "your team")  # CTFd in teams mode: you or a teammate, it cannot say which
    run.turn(z, "solve", flag="t{z}")
    run.do(iv.Approve(z))
    record = run.close()
    text = report(record)
    assert "- Solves: 3 (lanes 1, L1 0, teammates 0, you 1, your team on the platform 1)" in text.splitlines()
    assert "- Points: 60 of 60" in text.splitlines()
    timeline = sections(text, "### ")
    assert entries(timeline["X (misc, 10 pts): solved by you on the platform, before this run"])[-1] == (
        f"the platform lists it as solved by you, from before this run; flightdeck stopped {x} (the solve)"
    )
    assert entries(timeline["Y (misc, 20 pts): solved by your team on the platform"])[-1] == (
        f"the platform lists it as solved by your team; flightdeck stopped {y} (the solve)"
    )
    assert summary(record).splitlines()[1].endswith(
        "3 solved (lanes 1, L1 0, teammates 0, you 1, your team on the platform 1), 60 of 60 points"
    )


def test_an_older_logs_solve_by_your_team_is_the_platforms_not_a_teammates(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.deck.teammate_solved("x", "your team")  # how run.py recorded a solve CTFd listed, before platform solves
    text = report(run.close())
    assert "### X (misc, 10 pts): solved by your team on the platform" in text.splitlines()
    assert "- Solves: 1 (lanes 0, L1 0, teammates 0, you 0, your team on the platform 1)" in text.splitlines()


def test_a_warning_about_several_challenges_is_on_each_timeline_and_one_about_none_has_its_own_section(tmp_path):
    run = Script(tmp_path, team=False)
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    run.at(60)
    listed = "CTFd lists X, Y as solved for your account (by you or your team), and this run did not solve them"
    run.deck.warn(listed, data={"source": "ctfd", "solved": ["x", "y"]})  # as run.py warns in solo mode
    run.at(120)
    run.deck.warn("could not read the solves from CTFd: HTTP 400; flightdeck tries again in 60 s", data={"source": "ctfd"})
    record = run.close()
    text = report(record)
    timeline = sections(text, "### ")
    for heading in ("X (misc, 10 pts): not solved", "Y (misc, 20 pts): not solved"):
        assert items(timeline[heading])[-1] == f"T+00:01:00 · warning: {listed}"
    assert items(sections(text)["Warnings for the whole run"]) == [
        "T+00:02:00 · could not read the solves from CTFd: HTTP 400; flightdeck tries again in 60 s",
    ]
    assert "1 warning for the whole run: see the report" in summary(record).splitlines()


def test_an_l1_flag_is_a_solve_only_once_it_is_accepted(tmp_path):
    # You declined L1's flag (the deck now knows it is not the flag); L01 then found the real one.
    run = Script(tmp_path / "declined", flags={"x": "t{real}"})
    run.release([Challenge("x", "X", "misc", 100)])
    lane = run.lane("x")
    run.l1("x", "strings", "solved", ["t{fake}"], lane=lane, seconds=0.2)
    run.do(iv.Decline(lane))
    run.at(60)
    run.turn(lane, "cat flag.txt", flag="t{real}")
    run.do(iv.Approve(lane))
    declined = run.close()
    solve = solves(declined)["x"]
    assert (solve.by, solve.who, solve.flag) == ("lane", "L01", "t{real}")
    text = report(declined)
    glance = items(sections(text)["At a glance"])
    assert "Solves: 1 (lanes 1, L1 0, teammates 0, you 0)" in glance
    assert "Cost per solve: $0.01 per lane solve ($0.01 over 1 lane solve)" in glance
    x = entries(sections(text, "### ")["X (misc, 100 pts): solved by lane L01"])
    assert "L1 strings: solved in 0.2s, `t{fake}`" in x  # found, not the solve
    assert "L01 submitted `t{real}`: correct (the solve)" in x

    # L1's flag still waited for your approval when the run ended: found, never accepted.
    run = Script(tmp_path / "waiting", flags={"y": "t{y}"})
    run.release([Challenge("y", "Y", "misc", 250)])
    run.l1("y", "xor", "solved", ["t{maybe}"], lane=run.lane("y"), seconds=0.1)
    waiting = run.close()
    assert solves(waiting) == {}
    assert summary(waiting).splitlines()[1] == "0s, 1 challenge, 0 solved (lanes 0, L1 0, teammates 0, you 0), 0 of 250 points"
    assert "### Y (misc, 250 pts): not solved" in report(waiting).splitlines()

    # The writeups count the same solves.
    assert {cid: (s.lane, s.flag, s.l1) for cid, s in writeup.solves(declined).items()} == {"x": ("L01", "t{real}", None)}
    assert writeup.solves(waiting) == {}


def test_an_accepted_flag_l1_found_is_l1s_solve_though_a_lane_submitted_it(tmp_path):
    run = Script(tmp_path, flags={"z": "t{z}"})
    run.release([Challenge("z", "Z", "misc", 70)])
    lane = run.lane("z")
    run.l1("z", "rot", "candidate", ["t{z}"], lane=lane, seconds=0.1)
    run.do(iv.Approve(lane))
    record = run.close()
    solve = solves(record)["z"]
    assert (solve.by, solve.who, solve.flag, solve.lane) == ("l1", "rot", "t{z}", "L01")
    assert writeup.solves(record)["z"].l1.engine == "rot"  # the writeups credit the same engine
    text = report(record)
    assert "- Solves: 1 (lanes 0, L1 1, teammates 0, you 0)" in text.splitlines()
    z = entries(sections(text, "### ")["Z (misc, 70 pts): solved by L1 engine rot"])
    assert z[-2:] == [
        "L01 submitted `t{z}`: correct (the solve: the flag L1 engine rot found)",
        "L01 solved after 0 turns on small (0 tokens, $0.00): solved with t{z}",
    ]


def test_dollars_are_unknown_when_no_turn_had_a_price(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    run.turn(run.lane("y"), "look", tokens=3000, dollars=None)
    run.turn(run.lane("x"), "solve", tokens=1000, dollars=None, flag="t{x}")
    run.do(iv.Approve(run.lane("x")))
    record = run.close()
    text = report(record)
    glance = items(sections(text)["At a glance"])
    assert "Dollars: unknown (no turn had a price)" in glance
    assert "Spend: 4k tokens (12% cached), dollars unknown (no turn had a price)" in summary(record).splitlines()
    assert "Cost per solve: unknown in dollars; 4k tokens per lane solve" in glance  # 4,000 tokens, 1 lane solve
    spend = sections(text, "### ")
    assert "Ranked by tokens, since 2 lanes have no price." in spend["The 2 most expensive lanes"]
    assert [row[0] for row in table_rows(text)[-2:]] == ["L02", "L01"]  # by tokens: 3,000 then 1,000


def test_dollars_known_for_only_some_lanes_say_unknown_and_give_what_is_known(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    run.turn(run.lane("x"), "look", dollars=0.25, flag="t{x}")
    run.do(iv.Approve(run.lane("x")))
    run.turn(run.lane("y"), "look", dollars=0.5)
    run.turn(run.lane("y"), "look again", dollars=None)  # L02's priced turn still counts toward what is known
    record = run.close()
    text = report(record)
    assert "- Dollars: unknown (at least $0.75; 1 of 2 lanes had a turn with no price)" in text.splitlines()
    assert "- Cost per solve: unknown (at least $0.75 per lane solve); 3k tokens per lane solve" in text.splitlines()
    small = next(row for row in table_rows(text) if row[0] == "small")
    assert small == ["small", "3", "3,000", "25%", "unknown (at least $0.75; 1 of 3 turns had no price)"]
    assert "Spend: 3k tokens (25% cached), dollars unknown (at least $0.75; 1 of 2 lanes had a turn with no price)" in summary(record)


def test_dollars_unknown_in_every_lane_still_give_what_is_known(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    x, y = run.lane("x"), run.lane("y")
    run.turn(x, "look", dollars=0.50)
    run.turn(y, "look", dollars=0.90)
    run.turn(x, "look again", dollars=None)  # escalated to a model with no price, say
    run.turn(y, "look again", dollars=None)
    run.turn(x, "solve", dollars=None, flag="t{x}")
    run.do(iv.Approve(x))
    record = run.close()
    text = report(record)
    glance = items(sections(text)["At a glance"])
    assert "Dollars: unknown (at least $1.40; every lane had a turn with no price)" in glance
    assert "Cost per solve: unknown (at least $1.40 per lane solve); 5k tokens per lane solve" in glance
    x_line = sections(text, "### ")["X (misc, 10 pts): solved by lane L01"][0]
    assert x_line == "1 lane (L01), 3 turns, 3k tokens, dollars unknown (at least $0.50; the lane had a turn with no price)"
    assert ["small", "5", "5,000", "25%", "unknown (at least $1.40; 3 of 5 turns had no price)"] in table_rows(text)
    spend = "Spend: 5k tokens (25% cached), dollars unknown (at least $1.40; every lane had a turn with no price)"
    assert spend in summary(record).splitlines()


def test_a_turn_priced_at_nothing_had_a_price(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.turn(run.lane("x"), "look", dollars=0.0)  # a local model costs nothing
    run.turn(run.lane("x"), "look again", dollars=None)
    record = run.close()
    assert "- Dollars: unknown" in report(record).splitlines()  # not "no turn had a price"
    assert "Spend: 2k tokens (25% cached), dollars unknown" in summary(record).splitlines()


# ---------------------------------------------------------------------- the timeline


def test_the_timeline_tells_each_challenge_in_order_with_models_and_the_solve(played):
    board, record = played
    timeline = sections(report(record, board=board), "### ")
    alpha = timeline["Alpha (misc, 50 pts): solved by lane L01"]
    assert alpha[0] == "1 lane (L01), 3 turns, 3k tokens, $0.03"
    assert entries(alpha) == [
        "released (Board)",
        "L01 started on small",
        "L1 strings: none in 0.3s: no printable flag",  # the lane's L1 stage, before its first model call
        "L01 alert, Loop: the same command twice: cat note",
        "you: hint L01: decode the base64 \u2192 L01 reads it on its next turn",
        "L01 alert, Flag found: Candidate t{alpha} matches the flag format.",
        "you: approve L01 \u2192 t{alpha} is correct: Alpha solved by L01",
        "L01 submitted `t{alpha}`: correct (the solve)",
        "L01 solved after 3 turns on small (3k tokens, $0.03): solved with t{alpha}",
        "you: hint L01: too late, refused: L01 has finished (solved)",
    ]
    assert items(alpha)[0].startswith("T+00:00:00 \u00b7 ") and items(alpha)[-1].startswith("T+00:07:20 \u00b7 ")
    bravo = timeline["Bravo (web, 100 pts): solved by L1 engine sqli"]
    assert bravo[0] == "1 lane (L08), 0 turns, 0 tokens, $0.00"
    assert entries(bravo) == [
        "released (Board)",
        "L08 started on small",
        "L1 sqli: solved in 1.2s, `t{bravo}`",  # found; the solve is the platform accepting it
        "L08 alert, Flag found: Candidate t{bravo} matches the flag format.",
        "you: approve L08 \u2192 t{bravo} is correct: Bravo solved by L08",
        "L08 submitted `t{bravo}`: correct (the solve: the flag L1 engine sqli found)",
        "L08 solved after 0 turns on small (0 tokens, $0.00): solved with t{bravo}",
    ]
    charlie = entries(timeline["Charlie (cry, 200 pts): solved by lane L02"])  # the board's short code
    assert charlie[-1] == "L02 solved after 13 turns on small \u2192 big (25k tokens, $0.61): solved with t{charlie}"
    assert "you: escalate L02 \u2192 Escalated L02 from small to big" in charlie
    delta = entries(timeline["Delta (rev, 300 pts): solved by lane L09"])
    assert delta[3:6] == [
        "you: fork L03: angr it \u2192 Forked L03 \u2192 L09 on big",
        "L09 started on big, a fork of L03: angr it",
        "L09 alert, Flag found: Candidate t{delta} matches the flag format.",
    ]
    assert delta[-2:] == [
        "L09 solved after 3 turns on big (6k tokens, $0.15): solved with t{delta}",
        "L03 stopped after 5 turns on small (5k tokens, $0.05): L09 solved it",
    ]
    golf = entries(timeline["Golf (misc, 50 pts): solved by teammate wren"])
    assert golf[-1] == "teammate wren solved it; flightdeck stopped L06 (the solve)"
    hotel = entries(timeline["Hotel (web, 200 pts): not solved"])
    assert hotel[3:] == [
        "you: approve L07 \u2192 t{nope} was rejected; L07 carries on",
        "L07 submitted `t{nope}`: wrong",
        "you: redirect L07: read the source first \u2192 L07 has a new plan",
    ]
    india = timeline["India (web, 100 pts): not solved"]
    assert india[0] == "No lanes." and entries(india) == ["released (Board)", "teammate wren claimed it"]
    assert list(timeline)[:9] == [
        "Alpha (misc, 50 pts): solved by lane L01", "Bravo (web, 100 pts): solved by L1 engine sqli",
        "Charlie (cry, 200 pts): solved by lane L02", "Delta (rev, 300 pts): solved by lane L09",
        "Echo (pwn, 150 pts): not solved", "Foxtrot (for, 100 pts): not solved",
        "Golf (misc, 50 pts): solved by teammate wren", "Hotel (web, 200 pts): not solved",
        "India (web, 100 pts): not solved",
    ]


def test_warnings_and_budget_requests_are_on_the_timeline(tmp_path):
    run = Script(tmp_path)
    run.driver.fail["y"] = "no container runtime"
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)], token_cap=1000)
    run.turn(run.lane("x"), "big read", tokens=1200)  # over the cap: it asks for more
    text = report(run.close())
    timeline = sections(text, "### ")
    no_lane = timeline["Y (misc, 20 pts): not solved"]  # no lane, no transcript: its release names it
    assert entries(no_lane) == ["released (Board)", "warning: could not start a lane on Y: no container runtime"]
    x = entries(timeline["X (misc, 10 pts): not solved"])
    assert "L01 asked for approval: raise the cap by 50% (now 1k of 1k tokens)" in x
    assert "- Points: 0 of 30" in text.splitlines()


def test_the_release_comes_first_on_a_clock_that_moves_on_every_read(tmp_path):
    ticks = itertools.count()
    run = Script(tmp_path, clock=RunClock(lambda: float(next(ticks))))  # a second per read, so no two events share a time
    run.driver.fail["y"] = "no container runtime"
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    run.turn(run.lane("x"), "ls", flag="t{x}")
    record = run.close()
    kinds = [e.kind for e in record.events]
    assert kinds.index("lane.start") < kinds.index("warning") < kinds.index("release")  # as the deck logs a release
    timeline = sections(report(record), "### ")
    x = items(timeline["X (misc, 10 pts): not solved"])
    y = items(timeline["Y (misc, 20 pts): not solved"])
    assert [re.sub(r"^T\+\S+ · ", "", item) for item in x[:2]] == ["released (Board)", "L01 started on small"]
    assert [re.sub(r"^T\+\S+ · ", "", item) for item in y] == [
        "released (Board)", "warning: could not start a lane on Y: no container runtime",
    ]
    x_clocks, y_clocks = ([item.split(" · ")[0] for item in lines] for lines in (x, y))
    assert x_clocks == sorted(x_clocks) and y_clocks == sorted(y_clocks)  # the clock never runs backwards
    assert x_clocks[0] == x_clocks[1] == y_clocks[0] < y_clocks[1]  # the release, shown when it began: L01's start


# ---------------------------------------------------------------------- where lanes stalled


def test_each_stall_says_when_how_it_was_answered_and_whether_the_lane_then_solved(played):
    board, record = played
    text = report(record, board=board)
    stalled = sections(text)["Where lanes stalled"]
    assert stalled[0] == (
        "3 alerts on 3 lanes: 3 answered, 1 followed by that lane solving within 10 turns. "
        "Not stalls, so only in the timeline: 5 flag found alerts, 1 teammate solved / box in use alert."
    )
    stalls = sections(text, "### ")
    assert items(stalls["T+00:00:20 \u00b7 L01 on Alpha: Loop"]) == [
        "When: T+00:00:20, at turn 2",
        "Why: the same command twice: cat note",
        "Answered: 30s later, you: hint L01: decode the base64 \u2192 L01 reads it on its next turn",
        "Solved within 10 turns: yes, L01 solved it 1 turn later",
    ]
    assert items(stalls["T+00:00:30 \u00b7 L02 on Charlie: Stall"])[2:] == [
        "Answered: 7m later, you: escalate L02 \u2192 Escalated L02 from small to big",
        "Solved within 10 turns: no, L02 solved it 12 turns later",
    ]
    assert items(stalls["T+00:01:45 \u00b7 L03 on Delta: Effort vs value"]) == [
        "When: T+00:01:45, at turn 5",
        "Why: 5 turns of ghidra on a 300-pointer",
        "Answered: 1m later, you: fork L03: angr it \u2192 Forked L03 \u2192 L09 on big",
        "Solved within 10 turns: no, L03 did not solve it (lane L09 did)",
    ]


def test_a_stall_shows_the_lanes_last_steps_in_a_code_block(played):
    board, record = played
    text = report(record, board=board)
    fences = [t.content for t in walk(text) if t.type == "fence"]
    assert fences == ["cat note\ncat note\n", "python rsa.py\n", "ghidra pass 3\nghidra pass 4\nghidra pass 5\n"]


def test_an_alert_nobody_answered_says_why(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    run.turn(run.lane("x"), "ls", alerts=(Alert(AlertKind.STALL, "idle"),))
    run.turn(run.lane("x"), "ls", gave_up="nothing to do")
    run.turn(run.lane("y"), "ls", alerts=(Alert(AlertKind.LOOP, "ls again"),))
    run.do(iv.Pause(run.lane("y")))  # pausing is not an answer
    record = run.close()
    stalls = sections(report(record), "### ")
    assert items(stalls["T+00:00:00 \u00b7 L01 on X: Stall"])[2:] == [
        "Answered: no answer before the lane ended (gave up)", "Solved within 10 turns: no, L01 did not solve it",
    ]
    assert items(stalls["T+00:00:00 \u00b7 L02 on Y: Loop"])[2] == "Answered: no answer; the lane was still open when the run ended"


@pytest.mark.parametrize("turns, solved", [(10, "yes, L01 solved it 10 turns later"), (11, "no, L01 solved it 11 turns later")])
def test_solved_within_ten_turns_counts_the_lanes_turns_after_the_alert(tmp_path, turns, solved):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)], token_cap=10_000)
    lane = run.lane("x")
    run.turn(lane, "read", tokens=8500)  # 85% of the cap: a budget alert
    run.do(iv.Approve(lane))  # more budget
    for turn in range(1, turns + 1):
        run.turn(lane, f"try {turn}", tokens=10, flag="t{x}" if turn == turns else None)
    run.do(iv.Approve(lane))
    stall = items(sections(report(run.close()), "### ")["T+00:00:00 \u00b7 L01 on X: Budget"])
    assert stall[2].startswith("Answered: 0s later, you: approve L01 \u2192 L01's cap is now")
    assert stall[3] == f"Solved within 10 turns: {solved}"


@pytest.mark.parametrize("turns, solved", [(10, "yes, L01 solved it 10 turns later"), (11, "no, L01 solved it 11 turns later")])
def test_a_budget_alert_for_a_turn_with_no_price_is_at_that_turn(tmp_path, turns, solved):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)], dollar_cap=1.0)
    lane = run.lane("x")
    run.at(10)
    run.turn(lane, "turn one", dollars=0.01)
    run.at(20)
    run.turn(lane, "turn two", dollars=None)  # no price, so the $1 cap cannot hold: the deck alerts before logging the turn
    run.do(iv.Approve(lane))  # carry on without the dollar cap
    for turn in range(1, turns + 1):
        run.turn(lane, f"try {turn}", dollars=None, flag="t{x}" if turn == turns else None)
    run.do(iv.Approve(lane))
    record = run.close()
    alert = next(a for a in record.lanes[lane].actions if a.kind == "alert")
    assert alert.turn == 2  # the transcript's own account
    stall = items(sections(report(record), "### ")["T+00:00:20 · L01 on X: Budget"])
    assert stall[0] == "When: T+00:00:20, at turn 2"
    assert stall[3] == f"Solved within 10 turns: {solved}"


def test_two_alerts_of_a_kind_on_a_lane_each_have_their_own_turn_and_steps(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "ls")
    run.turn(lane, "ls", alerts=(Alert(AlertKind.LOOP, "ls twice"),))
    run.do(iv.Hint(lane, "stop listing"))  # answers the alert and clears it
    run.turn(lane, "ls -a")
    run.turn(lane, "ls -a", alerts=(Alert(AlertKind.LOOP, "ls -a twice"),))  # the same instant on this clock
    text = report(run.close())
    assert [line for line in text.splitlines() if line.startswith("- When:")] == [
        "- When: T+00:00:00, at turn 2", "- When: T+00:00:00, at turn 4",
    ]
    assert [t.content for t in walk(text) if t.type == "fence"] == ["ls\nls\n", "ls\nls -a\nls -a\n"]


# Made-up keys, built from pieces so no line here is shaped like a real one (.githooks/secret_scan.py).
OPENROUTER = "sk-" + "or-v1-" + "5f" * 32
GITHUB = "ghp" + "_" + "a1B2" * 9
PLANTED = "PLANTED-HERE"


def planted(folder: Path, text: str) -> Path:
    """The run folder as a run wrote it before its log and its transcripts were cleaned as
    they were written: `text` as it was wherever this run wrote PLANTED."""
    for path in [folder / "events.jsonl", *(folder / "lanes").glob("*.jsonl")]:
        path.write_text(path.read_text().replace(PLANTED, text))
    return folder


def test_a_report_quotes_an_older_run_folder_without_its_credentials(tmp_path):
    """An older run folder holds a host lane's commands and outputs as they were. The report
    reads it with each credential's value taken out (credentials.py), as a writeup does: the
    steps a stall quotes, the alert's reason (which quotes an output) and the lane's result
    keep each name and lose each value. The flags the run names stay whole, one shaped like a
    credential too."""
    flag = "t{TOKEN=c0ffee}"
    run = Script(tmp_path, flags={"x": "t{right}"})
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, f"cat keys.env  # {PLANTED}")
    run.turn(lane, f"submit {flag}", flag=flag)
    run.do(iv.Approve(lane))  # the platform says it is wrong
    run.turn(lane, f"cat keys.env  # {PLANTED}", alerts=(Alert(AlertKind.LOOP, f"The same output came back twice: {PLANTED}"),))
    run.turn(lane, "ls", gave_up=f"nothing more to try; {PLANTED}")
    run.close()
    record = load_run(planted(tmp_path, f"OPENROUTER_API_KEY={OPENROUTER} GITHUB_TOKEN={GITHUB}"))
    assert OPENROUTER in record.lanes[lane].actions[0].text and OPENROUTER in (tmp_path / "events.jsonl").read_text()
    text = report(record)
    assert "5f" * 32 not in text and "a1B2" * 9 not in text
    cleaned = "OPENROUTER_API_KEY=[redacted] GITHUB_TOKEN=[redacted]"
    assert [t.content for t in walk(text) if t.type == "fence"] == [
        f"cat keys.env  # {cleaned}\nsubmit {flag}\ncat keys.env  # {cleaned}\n",
    ]
    lines = [shown(t) for t in walk(text) if t.type == "inline"]
    assert f"Why: The same output came back twice: {cleaned}" in lines
    assert any(line.endswith(f"L01 submitted {flag}: wrong") for line in lines)
    assert any(line.endswith(f"nothing more to try; {cleaned}") for line in lines)


CTFD = "ctfd" + "_" + "0f" * 32


def test_a_report_cleans_an_older_run_folders_event_text_and_a_result_only_its_transcript_kept(tmp_path):
    """Two more places an older run folder holds a key as it was: the text of an event (a
    warning for the whole run, which has nothing else to show) and a lane's transcript, the
    only place a lane's result is left when the run stopped before its log had the lane's
    end. The report shows each with the key's name and not its value."""
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.deck.warn(f"could not pull the board with {PLANTED}")
    run.turn(lane, "ls", gave_up=f"the server wants {PLANTED}")
    run.close()
    log = tmp_path / "events.jsonl"
    log.write_text("".join(line for line in log.read_text().splitlines(keepends=True) if json.loads(line).get("kind") != "lane.end"))
    record = load_run(planted(tmp_path, f"CTFD_TOKEN={CTFD} OPENROUTER_API_KEY={OPENROUTER}"))
    assert not [e for e in record.events if e.kind == "lane.end"]
    assert CTFD in next(e.text for e in record.events if e.kind == "warning") and OPENROUTER in record.lanes[lane].result
    text = report(record)
    assert "0f" * 32 not in text and "5f" * 32 not in text
    cleaned = "CTFD_TOKEN=[redacted] OPENROUTER_API_KEY=[redacted]"
    lines = [shown(t) for t in walk(text) if t.type == "inline"]
    assert any(line.endswith(f"· could not pull the board with {cleaned}") for line in lines)  # under the run's warnings
    assert any(line.startswith(f"{lane} on X gave up") and line.endswith(f": the server wants {cleaned}") for line in lines)


def test_a_challenge_whose_id_or_name_looks_like_a_credential_keeps_it_in_the_log_the_report_and_the_score(tmp_path):
    """A challenge's id and name come from the board, and either can look like a credential:
    a slug with a Slack token's prefix, a name with a header in it. The log keeps them whole
    where its readers match on them (a release's challenge ids and board, the challenge a
    claim names), so the report names each challenge once, by its name, and practice scoring
    finds every challenge the run played on the board. A key a lane printed still loses its
    value."""
    folder = tmp_path / "board"
    folder.mkdir()
    (folder / "board.json").write_text(json.dumps({"event": "Test CTF", "flag_format": FLAG_FORMAT}))
    for cid, name, category in (("fortune", "Fortune Cookie: Part 2", "web"), ("xoxb-slack-bot", "xoxb Slack Bot", "misc")):
        (folder / cid).mkdir()
        (folder / cid / "challenge.json").write_text(json.dumps({"name": name, "category": category, "points": 50}))
    board = load_board(folder)
    run = Script(tmp_path / "run", flags={"xoxb-slack-bot": "t{slack}"})
    run.release([b.challenge for b in board.challenges])
    bot = run.lane("xoxb-slack-bot")
    run.do(iv.Claim("xoxb-slack-bot"))
    run.turn(bot, f"echo OPENROUTER_API_KEY={OPENROUTER}", flag="t{slack}")
    run.do(iv.Approve(bot))
    record = run.close()
    (release,) = [e for e in record.events if e.kind == "release"]
    assert release.data["challenges"] == ["fortune", "xoxb-slack-bot"]
    assert [(c["id"], c["name"]) for c in release.data["board"]] == [("fortune", "Fortune Cookie: Part 2"), ("xoxb-slack-bot", "xoxb Slack Bot")]
    (claim,) = [e for e in record.events if e.kind == "intervention" and e.data.get("intervention") == "claim"]
    assert claim.data["challenge"] == claim.challenge == "xoxb-slack-bot"
    text = report(record)
    assert "5f" * 32 not in text + (tmp_path / "run" / "events.jsonl").read_text()
    assert headings(text, "h3")[:3] == [
        "Fortune Cookie: Part 2 (web, 50 pts): not solved", "xoxb Slack Bot (misc, 50 pts): solved by lane L02", "Helped (0)",
    ]
    assert not [line for line in text.splitlines() if "no name or points" in line]
    card = score(record.dir / "events.jsonl", board)
    assert sorted(card.solved) == ["xoxb-slack-bot"]


@pytest.mark.parametrize("budget_approved", [False, True], ids=["left waiting", "approved"])
def test_a_flags_verdict_does_not_answer_a_budget_alert(tmp_path, budget_approved):
    run = Script(tmp_path, flags={"x": "t{right}"})
    run.release([Challenge("x", "X", "misc", 10)], token_cap=10_000)
    lane = run.lane("x")
    run.turn(lane, "read the dump", tokens=8500)  # 85% of the cap: a budget alert
    run.at(40)
    run.turn(lane, "strings dump", tokens=100, flag="t{wrong}")
    run.do(iv.Approve(lane))  # the flag's verdict: rejected
    run.at(80)
    run.turn(lane, "grep", tokens=100, flag="t{guess}")
    run.do(iv.Decline(lane))  # a flag's again: not submitted
    run.at(120)
    run.turn(lane, "more", tokens=2000)  # past the cap: it waits for more budget
    if budget_approved:
        run.at(150)
        run.do(iv.Approve(lane))  # the budget request itself
    record = run.close()
    stall = items(sections(report(record), "### ")["T+00:00:00 \u00b7 L01 on X: Budget"])
    stalls = next(line for line in summary(record).splitlines() if line.startswith("Stalls"))
    if budget_approved:
        assert stall[2] == "Answered: 2m later, you: approve L01 \u2192 L01's cap is now 11k of 15k tokens"
        assert stalls == "Stalls: 1 alert, 1 answered, 0 then solved within 10 turns"
    else:
        assert stall[2] == "Answered: no answer; the lane was still open when the run ended"
        assert stalls == "Stalls: 1 alert, 0 answered, 0 then solved within 10 turns"


def test_a_budget_request_queued_behind_a_flag_is_answered_once_it_comes_up(tmp_path):
    run = Script(tmp_path, flags={"x": "t{right}"})
    run.release([Challenge("x", "X", "misc", 10)], token_cap=1000)
    lane = run.lane("x")
    run.turn(lane, "cat dump", tokens=1200, flag="t{wrong}")  # over the cap, with a flag: the flag comes first
    run.at(30)
    run.do(iv.Approve(lane))  # the flag: rejected; the budget request comes up
    run.at(60)
    run.do(iv.Approve(lane))
    stall = items(sections(report(run.close()), "### ")["T+00:00:00 \u00b7 L01 on X: Budget"])
    assert stall[2] == "Answered: 1m later, you: approve L01 \u2192 L01's cap is now 1k of 2k tokens"


def test_a_refused_approve_leaves_the_flag_waiting_so_the_next_answers_the_flag(tmp_path):
    run = Script(tmp_path, flags={"x": "t{right}"})
    run.release([Challenge("x", "X", "misc", 10)], token_cap=10_000)
    lane = run.lane("x")
    run.turn(lane, "read the dump", tokens=8500)  # a budget alert, nothing waiting
    run.turn(lane, "strings dump", tokens=100, flag="t{wrong}")  # now a flag waits
    run.do(iv.TakeOver(lane))
    assert not run.do(iv.Approve(lane)).ok  # you have its shell: refused
    run.do(iv.HandBack(lane))
    run.do(iv.Approve(lane))  # the flag's verdict, not more budget
    stall = items(sections(report(run.close()), "### ")["T+00:00:00 \u00b7 L01 on X: Budget"])
    assert stall[2] == "Answered: no answer; the lane was still open when the run ended"


# ---------------------------------------------------------------------- interventions


def test_interventions_that_helped_and_those_with_no_effect_seen(played):
    board, record = played
    text = report(record, board=board)
    part = sections(text)["Interventions"]
    assert part[0].startswith("11 interventions, 1 refused.")
    found = sections(text, "### ")
    assert items(found["Helped (2)"]) == [
        "T+00:00:50 \u00b7 you: hint L01: decode the base64 \u2192 L01 reads it on its next turn (on Alpha); "
        "L01 solved it 1 turn and 20s later",
        "T+00:03:20 \u00b7 you: fork L03: angr it \u2192 Forked L03 \u2192 L09 on big (on Delta); L09 solved it 3 turns and 40s later",
    ]
    assert items(found["No effect seen (2)"]) == [
        "T+00:07:00 \u00b7 you: redirect L07: read the source first \u2192 L07 has a new plan (on Hotel); not solved",
        "T+00:08:20 \u00b7 you: escalate L02 \u2192 Escalated L02 from small to big (on Charlie); L02 solved it 12 turns and 20m later",
    ]
    assert found["Not judged (6)"] == ["approve 5, kill 1."]
    assert items(found["Refused, nothing changed (1)"]) == ["T+00:07:20 \u00b7 you: hint L01: too late, refused: L01 has finished (solved)"]


@pytest.mark.parametrize(
    "turns, seconds, helped",
    [(10, 1200, True), (11, 900, True), (11, 901, False)],
    ids=["10 turns", "15 minutes", "neither"],
)
def test_helped_means_a_solve_within_ten_turns_or_fifteen_minutes(tmp_path, turns, seconds, helped):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.at(100)
    run.do(iv.Redirect(lane, "try the obvious"))
    for turn in range(1, turns + 1):
        run.at(100 + seconds * turn / turns)
        run.turn(lane, f"try {turn}", flag="t{x}" if turn == turns else None)
    run.do(iv.Approve(lane))
    found = sections(report(run.close()), "### ")
    assert len(items(found["Helped (1)" if helped else "Helped (0)"])) == (1 if helped else 0)
    assert len(items(found["No effect seen (0)" if helped else "No effect seen (1)"])) == (0 if helped else 1)


@pytest.mark.parametrize(
    "step, at", [("escalate", 50), ("hint", 50), ("hint", 40)], ids=["escalate", "hint", "hint at the same instant"],
)
def test_a_step_taken_while_the_solving_flag_waited_did_not_help(tmp_path, step, at):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.at(40)
    run.turn(lane, "cat flag.txt", flag="t{x}")  # it waits for your approval
    run.at(at)  # at 40 only the log's order says the flag came first
    assert run.do(iv.Escalate(lane) if step == "escalate" else iv.Hint(lane, "try harder")).ok
    run.at(60)
    run.do(iv.Approve(lane))
    record = run.close()
    found = sections(report(record), "### ")
    assert found["Helped (0)"] == ["None."]
    (line,) = items(found["No effect seen (1)"])
    assert line.endswith("(on X); L01 solved it with a flag already waiting since T+00:00:40")
    assert "Interventions: 0 helped, 1 no effect seen" in summary(record).splitlines()


def test_a_hint_to_one_lane_did_not_help_another_lanes_flag_that_already_waited(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)], ["x", "x"])  # two lanes on X
    run.at(40)
    run.turn("L02", "cat flag.txt", flag="t{x}")
    run.at(50)
    run.do(iv.Hint("L01", "look at the headers"))
    run.at(60)
    run.do(iv.Approve("L02"))
    (line,) = items(sections(report(run.close()), "### ")["No effect seen (1)"])
    assert line.startswith("T+00:00:50 · you: hint L01: look at the headers")
    assert line.endswith("(on X); L02 solved it with a flag already waiting since T+00:00:40")


def test_a_flag_queued_behind_another_was_found_when_the_lane_proposed_it(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.at(40)
    run.turn(lane, "submit two", flag="t{a}")  # one reply with two candidates (agent/driver.py)...
    run.deck.report(lane, TurnReport(turn=False, flag="t{x}"))  # ...so t{x} waits behind t{a}
    run.at(50)
    run.do(iv.Hint(lane, "try harder"))
    run.at(60)
    run.do(iv.Approve(lane))  # t{a} is rejected and t{x} comes up only now
    run.do(iv.Approve(lane))
    (line,) = items(sections(report(run.close()), "### ")["No effect seen (1)"])
    assert line.endswith("(on X); L01 solved it with a flag already waiting since T+00:00:40")


@pytest.mark.parametrize("step", ["hint", "redirect"])
def test_a_hint_or_redirect_did_not_help_a_fresh_lane_that_never_got_it(tmp_path, step):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    first = run.lane("x")
    run.at(60)
    run.do(iv.Hint(first, "the key is in the file name") if step == "hint" else iv.Redirect(first, "read the file name"))
    run.at(70)
    run.do(iv.Kill(first, requeue=True))  # a fresh lane: no hints, none of the plan
    fresh = run.lane("x")
    run.at(130)
    run.turn(fresh, "cat note", flag="t{x}")
    run.do(iv.Approve(fresh))
    record = run.close()
    found = sections(report(record), "### ")
    assert found["Helped (0)"] == ["None."]
    (line,) = items(found["No effect seen (1)"])
    assert line.endswith(f"(on X); {fresh} solved it, a lane this {step} never reached")
    assert "Interventions: 0 helped, 1 no effect seen" in summary(record).splitlines()


def test_a_fork_helped_when_it_solved_and_a_hint_to_its_parent_before_or_after_did_not(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    parent = run.lane("x")
    run.at(10)
    run.do(iv.Hint(parent, "early hint"))  # the fork starts with its own approach, never the parent's hints
    run.at(20)
    run.do(iv.Fork(parent, "try binwalk"))
    fork = run.newest()
    run.at(30)
    run.do(iv.Hint(parent, "late hint"))
    run.at(40)
    run.turn(fork, "binwalk -e", flag="t{x}")
    run.do(iv.Approve(fork))
    found = sections(report(run.close()), "### ")
    (helped,) = items(found["Helped (1)"])
    assert helped.startswith(f"T+00:00:20 · you: fork {parent}: try binwalk") and helped.endswith(f"{fork} solved it 1 turn and 20s later")
    assert [line.split(" → ")[0] + " | " + line.split("(on X); ")[1] for line in items(found["No effect seen (2)"])] == [
        f"T+00:00:10 · you: hint {parent}: early hint | {fork} solved it, a lane this hint never reached",
        f"T+00:00:30 · you: hint {parent}: late hint | {fork} solved it, a lane this hint never reached",
    ]


def test_a_fork_did_not_help_when_its_parent_solved(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    parent = run.lane("x")
    run.at(10)
    run.do(iv.Fork(parent, "try binwalk"))
    fork = run.newest()
    run.at(20)
    run.turn(parent, "cat note", flag="t{x}")
    run.do(iv.Approve(parent))
    (line,) = items(sections(report(run.close()), "### ")["No effect seen (1)"])
    assert line.endswith(f"(on X); {parent} solved it, not the fork {fork}")


def test_an_escalation_helped_a_lane_re_queued_from_its_lane_which_starts_on_the_stronger_model(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    first = run.lane("x")
    run.at(10)
    run.do(iv.Escalate(first))
    run.at(20)
    run.do(iv.Kill(first, requeue=True))
    second = run.lane("x")
    run.at(25)
    run.do(iv.Kill(second, requeue=True))  # re-queued again: still the model the escalation chose
    third = run.lane("x")
    assert run.deck.lanes[third].model == "big"
    run.at(30)
    run.turn(third, "solve", flag="t{x}")
    run.do(iv.Approve(third))
    (line,) = items(sections(report(run.close()), "### ")["Helped (1)"])
    assert line.startswith(f"T+00:00:10 · you: escalate {first}") and line.endswith(f"(on X); {third} solved it 1 turn and 20s later")


def test_the_stall_and_the_interventions_tell_the_same_story(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    first = run.lane("x")
    run.turn(first, "ls", alerts=(Alert(AlertKind.STALL, "idle"),))
    run.at(30)
    run.do(iv.Hint(first, "look at the headers"))
    run.at(40)
    run.do(iv.Kill(first, requeue=True))
    fresh = run.lane("x")
    run.at(50)
    run.turn(fresh, "curl -I", flag="t{x}")
    run.do(iv.Approve(fresh))
    record = run.close()
    stall = items(sections(report(record), "### ")["T+00:00:00 · L01 on X: Stall"])
    assert stall[3] == f"Solved within 10 turns: no, {first} did not solve it (lane {fresh} did)"
    lines = summary(record).splitlines()
    assert "Stalls: 1 alert, 1 answered, 0 then solved within 10 turns" in lines
    assert "Interventions: 0 helped, 1 no effect seen" in lines  # the hint went to L01, which did not solve it


def test_a_solve_by_a_teammate_after_a_hint_is_not_the_hint_helping(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.do(iv.Hint(run.lane("x"), "look at the headers"))
    run.at(30)
    run.deck.teammate_solved("x", "wren")
    found = sections(report(run.close()), "### ")
    assert items(found["No effect seen (1)"]) == [
        "T+00:00:00 \u00b7 you: hint L01: look at the headers \u2192 L01 reads it on its next turn (on X); solved by teammate wren"
    ]


# ---------------------------------------------------------------------- spend


def test_spend_by_model_splits_an_escalated_lane_between_its_models(played):
    board, record = played
    rows = table_rows(report(record, board=board))
    assert rows[:3] == [
        ["Model", "Turns", "Tokens", "Cached", "Dollars"],
        ["big", "15", "30,000", "25%", "$0.75"],
        ["small", "15", "15,000", "25%", "$0.17"],
    ]


def test_the_five_most_expensive_lanes_by_dollars(played):
    board, record = played
    text = report(record, board=board)
    rows = table_rows(text)
    start = rows.index(["Lane", "Challenge", "Models", "Turns", "Tokens", "Cached", "Dollars", "Ended"])
    assert rows[start + 1:] == [
        ["L02", "Charlie", "small \u2192 big", "13", "25,000", "25%", "$0.61", "solved"],
        ["L09", "Delta", "big", "3", "6,000", "25%", "$0.15", "solved"],
        ["L03", "Delta", "small", "5", "5,000", "25%", "$0.05", "stopped"],
        ["L07", "Hotel", "small", "2", "2,000", "25%", "$0.04", "still open"],
        ["L01", "Alpha", "small", "3", "3,000", "25%", "$0.03", "solved"],
    ]
    assert "Ranked by dollars." in sections(text, "### ")["The 5 most expensive lanes"]


OUTSIDE_ROW = "of which outside a turn (a reply dropped on escalation, for one)"
TURN_END_ROW = "of which coding-agent CLIs' own cost of their turns, reported when each turn ended"
PART_OF = "A row that starts with \"of which\" is a part of the model rows above: each spend is in the row of the model that spent it."


def test_tokens_counted_outside_a_turn_are_in_their_models_row_and_shown_as_a_part_of_it(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.turn(run.lane("x"), "look", tokens=1000, dollars=0.1)
    run.deck.report(run.lane("x"), TurnReport(turn=False, tokens=400, dollars=0.04))  # a reply dropped on escalation
    text = report(run.close())
    rows = table_rows(text)
    assert rows[1] == ["small", "1", "1,400", "18%", "$0.14"]
    assert rows[2] == [OUTSIDE_ROW, "-", "400", "0%", "$0.04"]
    assert rows[3][0] == "Lane"  # no other row: the run's spend is the model rows', and nothing more
    assert PART_OF in sections(text, "### ")["By model"]


def test_spend_counts_for_the_model_that_spent_it_not_the_lanes_model_at_the_time(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "look", tokens=1000, dollars=0.1)
    assert run.do(iv.Escalate(lane)).ok and run.deck.lanes[lane].model == "big"
    run.turn(lane, "look again", tokens=2000, cached=0, dollars=0.5)  # the log has the lane on "big" from here
    # the small model's reply, dropped on the escalation, logged after a turn of "big"
    run.deck.report(lane, TurnReport(turn=False, tokens=400, dollars=0.04, model="small", why="a reply dropped on escalation"))
    text = report(run.close())
    rows = table_rows(text)
    assert rows[1:4] == [
        ["big", "1", "2,000", "0%", "$0.50"],
        ["small", "1", "1,400", "18%", "$0.14"],
        [OUTSIDE_ROW, "-", "400", "0%", "$0.04"],
    ]
    assert ["L01", "X", "small → big", "2", "3,400", "7%", "$0.64", "still open"] in rows  # no third model: small spent it
    assert "L01 spent 400 tokens outside a turn ($0.04): a reply dropped on escalation" in entries(
        sections(text, "### ")["X (misc, 10 pts): not solved"]
    )


# what agent/external.py said as the why of a CLI's report at a turn's end before spend events were marked turn_end
EARLIER_TURN_END = "what claude reported when its turn ended: the turn's cost, and tokens no step carried"
EARLIER_CUT_TURN = "what claude reported for a turn it was stopped in (an escalation, or the lane's end)"


@pytest.mark.parametrize("marked", [True, False], ids=["marked turn_end", "an earlier log's why"])
def test_what_a_cli_reports_at_a_turns_end_is_its_models_own_cost_and_never_spend_outside_a_turn(tmp_path, marked):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "ls", tokens=1000, cached=0, dollars_later=True)  # a coding-agent CLI's steps carry no cost
    run.deck.report(lane, TurnReport(turn=False, tokens=200, dollars=0.03, turn_end=True, model="small", why=EARLIER_TURN_END))
    run.turn(lane, "cat note", tokens=1000, cached=0, dollars_later=True)
    assert run.do(iv.Escalate(lane)).ok
    # the small model's turn, cut by the escalation, reported while the lane runs "big"
    run.deck.report(lane, TurnReport(turn=False, tokens=300, dollars=0.05, turn_end=True, model="small", why=EARLIER_CUT_TURN))
    run.turn(lane, "strings blob", tokens=1000, cached=0, dollars_later=True, flag="t{x}")
    assert run.do(iv.Approve(lane)).ok and run.deck.lanes[lane].finished  # solved in the middle of its turn
    # what claude reported once it was stopped: after the lane's end
    run.deck.report(lane, TurnReport(turn=False, tokens=100, dollars=0.2, turn_end=True, model="big", why=EARLIER_CUT_TURN))
    run.close()
    if not marked:  # a log from before spend events were marked turn_end: its why says what it was
        rewrite(tmp_path / "events.jsonl", lambda e: {**e, "data": {k: v for k, v in e["data"].items() if k != "turn_end"}}
                if e.get("kind") == "spend" else e)
        assert '"turn_end"' not in (tmp_path / "events.jsonl").read_text()
    text = report(load_run(tmp_path))
    rows = table_rows(text)
    assert rows[1:4] == [
        ["small", "2", "2,500", "0%", "$0.08"],
        ["big", "1", "1,100", "0%", "$0.20"],
        [TURN_END_ROW, "-", "600", "0%", "$0.28"],
    ]
    assert not any(row[0].endswith("outside a turn (a reply dropped on escalation, for one)") for row in rows)
    assert ["L01", "X", "small → big", "3", "3,600", "0%", "$0.28", "solved"] in rows
    assert "- Dollars: $0.28" in text.splitlines()
    timeline = entries(sections(text, "### ")["X (misc, 10 pts): solved by lane L01"])
    assert not any("spent" in entry for entry in timeline)  # summed like the turns, never listed as spend outside one
    assert "Spend: 4k tokens (0% cached), $0.28, $0.28 per lane solve" in summary(load_run(tmp_path)).splitlines()


def test_a_cli_models_dollars_say_how_many_of_its_turns_had_no_price(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "ls", tokens=1000, cached=0, dollars_later=True)
    run.deck.report(lane, TurnReport(turn=False, tokens=200, dollars=0.03, turn_end=True))
    run.turn(lane, "cat note", tokens=1000, cached=0, dollars_later=True)
    run.deck.report(lane, TurnReport(turn=False, dollars=None, turn_end=True))  # it exited in the turn: no price for it
    rows = table_rows(report(run.close()))
    assert rows[1] == ["small", "2", "2,200", "0%", "unknown (at least $0.03; 1 of 2 CLI turns had no known cost)"]
    assert rows[2] == [TURN_END_ROW, "-", "200", "0%", "unknown (at least $0.03)"]


@pytest.mark.parametrize("transcripts", [True, False], ids=["with transcripts", "log only"])
def test_a_cli_turn_whose_cost_never_came_leaves_the_lanes_dollars_unknown_not_settled(tmp_path, transcripts):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "ls", dollars_later=True)  # a coding-agent CLI's step: the cost comes when its turn ends
    run.deck.report(lane, TurnReport(turn=False, tokens=200, dollars=0.03, turn_end=True, why="the turn's cost"))
    run.turn(lane, "cat note", dollars_later=True)  # the run stops in this turn: its cost never comes
    run.close()
    if not transcripts:
        for path in (tmp_path / "lanes").iterdir():
            path.unlink()
    text = report(load_run(tmp_path))
    assert "- Dollars: unknown (at least $0.03; the lane had a turn with no price)" in text.splitlines()
    rows = table_rows(text)
    assert ["L01", "X", "small", "2", "2,200", "23%", "unknown", "still open"] in rows
    # its model's row and the CLIs' own cost are not settled numbers either
    assert rows[1:3] == [["small", "2", "2,200", "23%", "unknown (at least $0.03; 1 of 2 CLI turns had no known cost)"],
                         [TURN_END_ROW, "-", "200", "0%", "unknown (at least $0.03)"]]
    notes = items(sections(text)["Problems reading the run"])
    assert "L01's coding-agent CLI never reported what its last turn cost: its dollars are not fully known" in notes


def test_a_cli_lanes_steps_are_not_turns_with_no_price(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "ls", dollars_later=True)
    run.deck.report(lane, TurnReport(turn=False, tokens=200, dollars=0.03, turn_end=True, why="the turn's cost"))
    text = report(run.close())
    assert "- Dollars: $0.03" in text.splitlines()
    assert ["L01", "X", "small", "1", "1,200", "21%", "$0.03", "still open"] in table_rows(text)


def test_spend_outside_a_turn_keeps_its_price_after_a_turn_with_none(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "look", tokens=1000, dollars=0.1)
    run.turn(lane, "look again", tokens=500, dollars=None)  # on a model with no price: the lane's dollars are unknown
    run.deck.report(lane, TurnReport(turn=False, tokens=400, dollars=0.04, why="a reply dropped on escalation"))
    record = run.close()
    text = report(record)
    rows = table_rows(text)
    outside = next(row for row in rows if row[0].endswith("outside a turn (a reply dropped on escalation, for one)"))
    assert outside == [OUTSIDE_ROW, "-", "400", "0%", "$0.04"]  # the API's own price
    assert ["small", "2", "1,900", "26%", "unknown (at least $0.14; 1 of 3 turns and spends had no price)"] in rows
    assert "- Dollars: unknown (at least $0.14; the lane had a turn with no price)" in text.splitlines()
    assert "L01 spent 400 tokens outside a turn ($0.04): a reply dropped on escalation" in entries(
        sections(text, "### ")["X (misc, 10 pts): not solved"]
    )


def test_an_older_log_without_spend_events_cannot_price_what_a_lane_with_no_price_spent_outside_a_turn(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    lane = run.lane("x")
    run.turn(lane, "look", tokens=1000, dollars=0.1)
    run.turn(lane, "look again", tokens=500, dollars=None)
    run.deck.report(lane, TurnReport(turn=False, tokens=400, dollars=0.04))
    run.close()
    text = report(load_run(older(tmp_path)))  # only the transcript's totals say what was spent outside a turn
    rows = table_rows(text)
    # in no model's row (the transcript cannot say which model spent it), so a row of its own, not a part
    assert rows[1:3] == [
        ["small", "2", "1,500", "33%", "unknown (at least $0.10; 1 of 2 turns had no price)"],
        ["outside a turn (a reply dropped on escalation, for one)", "-", "400", "0%", "unknown"],  # not $0.00
    ]
    assert PART_OF not in sections(text, "### ")["By model"]
    assert "- Dollars: unknown (at least $0.10; the lane had a turn with no price)" in text.splitlines()


def test_the_report_the_scorecard_and_the_console_give_the_same_floor_for_dollars(tmp_path):
    """A priced turn, a reply dropped on escalation whose cost the API reported, then a turn on
    a model with no price; and a lane priced throughout. $0.80 had a price: every report says so."""
    board = load_board(write_board(tmp_path / "board"))
    run = Script(tmp_path / "run", flags=FLAGS)
    run.release([b.challenge for b in board.challenges if b.challenge.id in ("alpha", "bravo")])
    alpha, bravo = run.lane("alpha"), run.lane("bravo")
    run.turn(alpha, "cat note", dollars=0.20)
    run.deck.report(alpha, TurnReport(turn=False, tokens=1240, dollars=0.30, why="a reply dropped on escalation"))
    run.do(iv.Escalate(alpha))
    run.turn(alpha, "submit", dollars=None, flag="t{alpha}")  # the big model has no price anywhere
    run.do(iv.Approve(alpha))
    for n in range(3):
        run.turn(bravo, f"try {n}", dollars=0.10, flag="t{bravo}" if n == 2 else None)
    run.do(iv.Approve(bravo))
    assert run.deck.totals()[1] == pytest.approx(0.80)  # the console's header: tokens, known dollars, unknown?
    record = run.close()
    assert "- Dollars: unknown (at least $0.80; 1 of 2 lanes had a turn with no price)" in report(record).splitlines()
    assert record.lanes[alpha].known_dollars == pytest.approx(0.50)
    card = score(record.dir / "events.jsonl", board)
    assert card.known_dollars == pytest.approx(0.80) and card.dollars is None
    assert "Spent 6k tokens · $0.80+ · $0.40+ per lane solve" in scorecard(card).splitlines()


# ---------------------------------------------------------------------- lanes that gave up or were killed


def test_lanes_that_gave_up_or_were_killed_with_their_reasons(played):
    board, record = played
    part = sections(report(record, board=board))["Lanes that gave up or were killed"]
    assert items(part) == [
        "L03 on Delta was stopped at T+00:04:00 after 5 turns: L09 solved it",
        "L04 on Echo gave up at T+00:05:10 after 2 turns: no leak found",
        "L05 on Foxtrot was killed at T+00:05:30 after 1 turn: by the player; parked",
        "L06 on Golf was stopped at T+00:05:50 after 1 turn: wren solved Golf",
        "L07 on Hotel (run, 2 turns)",
    ]
    assert "Still open when the run ended:" in part


# ---------------------------------------------------------------------- the summary


def test_the_summary_is_a_few_plain_lines(played):
    board, record = played
    lines = summary(record, board=board).splitlines()
    assert lines == [
        "Post-flight: Test CTF, run run",
        "28m, 9 challenges, 5 solved (lanes 3, L1 1, teammates 1, you 0), 700 of 1250 points",
        "Spend: 45k tokens (25% cached), $0.92, $0.31 per lane solve",
        "Stalls: 3 alerts, 3 answered, 1 then solved within 10 turns",
        "Interventions: 2 helped, 2 no effect seen",
        "Lanes: 9 (4 solved, 1 gave up, 1 killed, 2 stopped, 1 still open)",  # L08 ended solved; the solve is L1's
    ]
    assert summary(record).splitlines()[0] == "Post-flight: test, run run"  # the run log's own name for the event


# ---------------------------------------------------------------------- damaged and unfinished runs


def test_lines_that_could_not_be_read_are_reported(played):
    board, record = played
    with (record.dir / "events.jsonl").open("a") as handle:
        handle.write('{"kind": "turn", "at": 9\n')  # a crash mid-write
        handle.write(json.dumps({"kind": "board", "at": 1, "data": {}}) + "\n")
        handle.write(json.dumps({"kind": "zz.future", "at": 1, "data": {}}) + "\n")
    record = load_run(record.dir)
    text = report(record, board=board)
    problems = items(sections(text)["Problems reading the run"])
    assert problems[0].startswith("events.jsonl:") and "not JSON" in problems[0]
    assert "events this report does not read: board (1), zz.future (1)" in problems
    assert summary(record, board=board).splitlines()[-1] == "2 problems reading the run: see the report"


def test_a_run_that_crashed_says_so_and_counts_open_lanes_from_the_event_log(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.turn(run.lane("x"), "look", tokens=700, dollars=0.07)
    run.turn(run.lane("x"), "look", tokens=300, dollars=0.03)
    run.close()
    lines = (tmp_path / "events.jsonl").read_text().splitlines()
    (tmp_path / "events.jsonl").write_text("\n".join(lines[:-1]) + "\n")  # the crash lost run-end...
    (tmp_path / "lanes" / "L01.jsonl").unlink()  # ...and the open lane's transcript
    record = load_run(tmp_path)
    text = report(record)
    glance = items(sections(text)["At a glance"])
    assert glance[1].endswith("ended no run-end line (the run did not close cleanly)")
    assert "Tokens: 1k (1,000), 50% cached" in glance and "Dollars: $0.10" in glance
    problems = items(sections(text)["Problems reading the run"])
    assert "L01 has no transcript in lanes/ (the run did not close cleanly?): its numbers come from the event log" in problems
    assert "The run did not close cleanly (no run-end line)." in summary(record)


def test_values_of_the_wrong_type_become_unknowns_not_crashes_or_zeros(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.close()
    odd = [
        {"kind": "release", "at": 1, "data": {"challenges": "x"}},  # not a list
        {"kind": "turn", "at": 2, "lane": "L01", "challenge": "x", "data": {"turn": "two", "tokens": "many", "dollars": "1"}},
        {"kind": "l1", "at": 3, "challenge": "x", "data": {"engine": 7, "status": "solved", "flags": "t{x}", "seconds": "fast"}},
        {"kind": "intervention", "at": 4, "lane": "L01", "data": {"intervention": "hint", "text": ["a"]}},
        {"kind": "outcome", "at": 4, "lane": "L01", "data": {"intervention": "hint", "ok": "yes"}},
        {"kind": "submit", "at": 5, "lane": "L01", "challenge": "x", "data": {"flag": 123, "correct": "yes"}},
    ]
    with (tmp_path / "events.jsonl").open("a") as handle:
        handle.writelines(json.dumps(line) + "\n" for line in odd)
    text = report(load_run(tmp_path))
    x = entries(sections(text, "### ")["X (misc, 10 pts): not solved"])  # no flag was accepted
    assert x[-3:] == [
        "L1 7: solved",  # no flags list and no number of seconds: neither is made up
        "you: hint L01: \\['a'\\] (no outcome in the log)",  # its "ok" is not true or false
        "L01 submitted `123`: no verdict",
    ]
    assert ["(none)", "1", "0", "0%", "unknown"] in table_rows(text)  # a price that is not a number is unknown, not $0


def rewrite(path: Path, change) -> None:
    """Rewrite a JSONL file of the run, line by line (json writes NaN and Infinity as is)."""
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    path.write_text("".join(json.dumps(change(line)) + "\n" for line in lines))


def older(folder: Path) -> Path:
    """The run folder as a format 1 log has it: no format, no event or names in the releases,
    no spend events, and transcripts without known_dollars."""

    def strip(line: dict) -> dict:
        if line.get("kind") == "run-start":
            return {k: v for k, v in line.items() if k != "format"}
        if line.get("kind") == "release":
            return {**line, "data": {k: v for k, v in line["data"].items() if k not in ("event", "board")}}
        return line

    rewrite(folder / "events.jsonl", strip)
    events = folder / "events.jsonl"
    events.write_text("".join(line + "\n" for line in events.read_text().splitlines() if '"kind": "spend"' not in line))
    for transcript in (folder / "lanes").glob("*.jsonl"):
        rewrite(transcript, lambda line: {k: v for k, v in line.items() if k != "known_dollars"})
    return folder


def test_times_that_are_not_times_show_as_unknown_not_a_crash(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.at(10)
    run.turn(run.lane("x"), "ls", gave_up="nothing here")
    run.close()
    rewrite(tmp_path / "events.jsonl", lambda e: {**e, "at": float("nan")} if e.get("kind") == "lane.end" else e)
    with (tmp_path / "events.jsonl").open("a") as handle:  # json reads all of these as floats
        for at in ("NaN", "Infinity", "1e400", "-5"):
            handle.write('{"kind": "warning", "at": %s, "text": "odd %s", "challenge": "x", "data": {}}\n' % (at, at))
    record = load_run(tmp_path)
    text = report(record)
    x = items(sections(text, "### ")["X (misc, 10 pts): not solved"])
    assert x[-5:] == [
        "T+? · L01 gave up after 1 turn on small (1k tokens, $0.01): nothing here",
        "T+? · warning: odd NaN", "T+? · warning: odd Infinity", "T+? · warning: odd 1e400", "T+? · warning: odd -5",
    ]
    assert "- Duration: 10s (first to last event)" in text.splitlines()
    assert items(sections(text)["Lanes that gave up or were killed"]) == ["L01 on X gave up after 1 turn: nothing here"]
    assert (
        "5 events in the run log have a time that is not one (not a number, infinite or negative): "
        "shown as T+? and left out of the duration"
    ) in items(sections(text)["Problems reading the run"])
    assert summary(record).splitlines()[1].startswith("10s, 1 challenge, 0 solved")
    result = runner.invoke(mounted(), ["report", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "report.md").read_text(encoding="utf-8") == text


def test_numbers_that_are_not_finite_are_unknown_not_a_crash(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.turn(run.lane("x"), "ls", dollars=0.5)
    run.close()
    rewrite(tmp_path / "lanes" / "L01.jsonl", lambda line: {**line, "dollars": float("inf")} if "lane" in line else line)
    with (tmp_path / "events.jsonl").open("a") as handle:  # a count too big for a float, and a price that is not a number
        handle.write('{"kind": "turn", "at": 1, "lane": "L01", "challenge": "x", "data": {"model": "small", '
                     '"tokens": %s, "dollars": NaN}}\n' % ("9" * 400))
    text = report(load_run(tmp_path))
    rows = table_rows(text)
    assert ["small", "2", "1,000", "25%", "unknown (at least $0.50; 1 of 2 turns had no price)"] in rows  # nothing made up
    assert ["L01", "X", "small", "1", "1,000", "25%", "unknown", "still open"] in rows  # the transcript's price is no number
    assert "- Dollars: unknown (at least $0.50; the lane had a turn with no price)" in text.splitlines()


def test_a_run_with_nothing_in_it_still_reports(tmp_path):
    run = Script(tmp_path)
    text = report(run.close())
    parts = sections(text)
    assert parts["Timeline"] == ["No challenges in this run."]
    assert parts["Spend"] == ["No lanes ran, so no model spend."]
    assert parts["Lanes that gave up or were killed"] == ["None."]
    assert "- Duration: 0s (first to last event)" in text.splitlines()


# ---------------------------------------------------------------------- hostile text

EVIL = (
    "x | <img src=x onerror=alert(1)> ![p](http://evil.example/p.png) [c](javascript:alert(1)) "
    "`t` *b* _i_ ~~s~~ $m$ &amp; \\| #h\n# Heading\x1b[31m\u202e!"
)
EVIL_FLAG = "t{``` ` | <b>x</b> \\}"
EVIL_STEP = "echo ```` <b>|</b>\n# not a heading\n```"


def evil_run(folder: Path):
    """A run where every text a challenge, lane, player or engine controls is hostile, the
    event's name too. Lanes: L01 e1, L02 e2, L03 e3, (L04: e5's start fails), L05 e4 (L1
    solves it), L06 forks L01."""
    run = Script(folder, flags={"e1": EVIL_FLAG, "e4": "t{<b>`|`}"}, models=("m<b>|1", "m`2`"), event=EVIL)
    run.driver.fail["e5"] = "boom <b>|x\n# h"
    run.release(
        [Challenge(f"e{n}", EVIL + str(n), "web<b>|", 10) for n in range(1, 6)], ["e1", "e2", "e3", "e5", "e4"],
        label="Wave <b>1</b> | x",
    )
    run.l1("e4", "eng<i>|`x`", "solved", ["t{<b>`|`}"], lane=run.lane("e4"), notes="<details>open</details> | [x](http://e)")
    run.do(iv.Approve(run.lane("e4")))
    lane = run.lane("e1")
    run.turn(lane, EVIL_STEP, alerts=(Alert(AlertKind.LOOP, EVIL),))
    run.do(iv.Hint(lane, EVIL))
    run.do(iv.Fork(lane, EVIL))
    run.turn(lane, EVIL_STEP, flag=EVIL_FLAG)
    run.do(iv.Approve(lane))
    run.turn(run.lane("e2"), "x", gave_up="1. not a list\n- nor this\n> nor a quote\n===")
    run.deck.teammate_solved("e3", "<u>mate</u>|x")
    run.deck.warn(EVIL)  # a warning that belongs to no challenge
    return run.close()


def test_hostile_text_renders_as_itself_never_as_markup(tmp_path):
    text = report(evil_run(tmp_path))
    assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", text)
    kinds = {token.type for token in walk(text)}
    assert not kinds & FORBIDDEN, kinds & FORBIDDEN
    assert all(t.markup.startswith("#") for t in walk(text) if t.type == "heading_open")  # no "===" heading
    assert all(t.level == 0 for t in walk(text) if t.type == "bullet_list_open")  # no list nested by a value
    assert headings(text, "h1") == ["Post-flight: " + fold(EVIL)]  # the event's name, from the run log
    assert headings(text, "h2") == [
        "At a glance", "Timeline", "Warnings for the whole run", "Where lanes stalled", "Interventions", "Spend",
        "Lanes that gave up or were killed",  # the run log names every challenge: nothing to say about reading it
    ]
    shown_lines = [shown(t) for t in PARSER.parse(text) if t.type == "inline"]
    assert f"T+00:00:00 · {fold(EVIL)}" in shown_lines  # the run-wide warning renders as itself
    h3 = headings(text, "h3")
    assert f"{fold(EVIL)}1 (web<b>|, 10 pts): solved by lane L01" in h3
    assert f"{fold(EVIL)}4 (web<b>|, 10 pts): solved by L1 engine eng<i>|`x`" in h3
    assert f"T+00:00:00 \u00b7 L01 on {fold(EVIL)}1: Loop" in h3
    assert all("Heading" not in h or fold(EVIL) in h for h in h3)


def test_hostile_text_keeps_to_its_table_cell(tmp_path):
    text = report(evil_run(tmp_path))
    rows = table_rows(text)
    assert ["m<b>|1", "3", "3,000", "25%", "$0.03"] in rows  # L01's two turns and L02's one
    lanes = {row[0]: row for row in rows if row[0] in ("L01", "L02", "L03", "L05", "L06")}
    assert [lanes[lane][1] for lane in ("L01", "L02", "L03", "L05", "L06")] == [fold(EVIL) + n for n in "12341"]
    assert lanes["L01"][2] == "m<b>|1" and lanes["L06"][2] == "m`2`" and lanes["L06"][7] == "stopped"


def test_flags_are_code_spans_and_commands_are_fenced_whole(tmp_path):
    text = report(evil_run(tmp_path))
    codes = [t.content for t in walk(text) if t.type == "code_inline"]
    assert fold(EVIL_FLAG) in codes and "t{<b>`|`}" in codes
    fences = [t for t in walk(text) if t.type == "fence"]
    assert [f.content for f in fences] == [fold(EVIL_STEP) + "\n"]
    assert fences[0].markup == "`````"  # longer than the four backticks inside


def test_hostile_text_is_never_a_link_a_reader_could_not_see(tmp_path):
    text = report(evil_run(tmp_path))
    tokens = list(walk(text, LINKIFY))
    links = [(t.attrs.get("href"), tokens[i + 1].content) for i, t in enumerate(tokens) if t.type == "link_open"]
    assert links, "linkify should still find the bare URLs"
    for href, label in links:
        assert href in (label, "http://" + label) and href.startswith(("http://", "https://")), (href, label)
    assert not any(t.type in ("image", "html_inline", "html_block") for t in tokens)


def test_hostile_text_in_the_summary_is_folded_onto_its_line(tmp_path):
    record = evil_run(tmp_path)
    text = summary(record)
    assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e]", text)
    lines = text.splitlines()
    assert len(lines) == 7  # title, play, spend, stalls, interventions, lanes, warnings: no line of its own
    assert lines[0] == f"Post-flight: {fold(EVIL)}, run {tmp_path.name}"
    assert lines[5] == "Lanes: 5 (2 solved, 1 gave up, 2 stopped)"
    assert lines[6] == "1 warning for the whole run: see the report"


def test_md_helpers_pick_fences_longer_than_any_backtick_run():
    assert md_code("plain") == "`plain`"
    assert md_code("a``b") == "```a``b```"
    assert md_code("`edge`") == "`` `edge` ``"
    assert shown(PARSER.parse(md_code("`edge`"))[1]) == "`edge`"
    assert md_fence(["x", "``` and `````"]) == ["``````text", "x", "``` and `````", "``````"]
    assert md_fence(["a\nb"]) == ["```text", "a \u23ce b", "```"]
    assert md_text("- item") == "\\- item" and md_text("1. item") == "1\\. item"
    assert md_text("a" * 300) == "a" * 199 + "\u2026"
    assert md_text("$x$ costs $5") == "\\$x\\$ costs \\$5"  # never TeX math where a renderer has it (GitHub does)


# ---------------------------------------------------------------------- the command


def mounted() -> typer.Typer:
    """The `flightdeck` command the player runs: cli.py mounts `report` there."""
    return cli.app


runner = CliRunner()


def test_report_writes_report_md_and_prints_the_summary(played):
    board, record = played
    result = runner.invoke(mounted(), ["report", str(record.dir), "--board", str(board_dir(record))])
    assert result.exit_code == 0, result.output
    written = record.dir / "report.md"
    assert written.read_text(encoding="utf-8") == report(load_run(record.dir), board=board)
    assert result.output == summary(load_run(record.dir), board=board) + f"report: {written}\n"


def board_dir(record) -> Path:
    return record.dir.parent / "board"


def test_report_replaces_an_old_report_and_never_follows_a_symlink(played, tmp_path):
    _, record = played
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    (record.dir / "report.md").symlink_to(outside)
    result = runner.invoke(mounted(), ["report", str(record.dir)])
    assert result.exit_code == 0, result.output
    assert outside.read_text() == "keep me"
    assert not (record.dir / "report.md").is_symlink()
    assert (record.dir / "report.md").read_text(encoding="utf-8") == report(load_run(record.dir))
    assert not list(record.dir.glob(".report.*"))  # no temporary file left behind


def test_report_on_a_folder_that_is_not_a_run_fails_with_the_reason(tmp_path):
    result = runner.invoke(mounted(), ["report", str(tmp_path)])
    assert result.exit_code == 2
    assert "no events.jsonl (is this a flightdeck run folder?)" in result.output
    assert not (tmp_path / "report.md").exists()


def test_report_with_a_board_that_cannot_be_read_fails_with_the_reason(played, tmp_path):
    _, record = played
    empty = tmp_path / "empty-board"
    empty.mkdir()
    result = runner.invoke(mounted(), ["report", str(record.dir), "--board", str(empty)])
    assert result.exit_code == 2
    assert "--board:" in result.output and "no challenge directories" in result.output
    assert not (record.dir / "report.md").exists()


def test_report_takes_the_event_log_the_run_printed_too(played):
    _, record = played
    result = runner.invoke(mounted(), ["report", str(record.dir / "events.jsonl")])
    assert result.exit_code == 0, result.output
    assert (record.dir / "report.md").read_text(encoding="utf-8") == report(load_run(record.dir))
    other = runner.invoke(mounted(), ["report", str(record.dir / "lanes" / "L01.jsonl")])
    assert other.exit_code == 2
    assert "not a run folder; give the run folder (the one holding events.jsonl) or its events.jsonl" in other.output


def test_report_needs_an_existing_folder(tmp_path):
    result = runner.invoke(mounted(), ["report", str(tmp_path / "nope")])
    assert result.exit_code == 2
    assert "Invalid value for 'RUN_DIR'" in result.output  # not "No such command"


needs_permissions = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="not run: file permissions do not stop root"
)


def small_run(folder: Path) -> Path:
    run = Script(folder)
    run.release([Challenge("x", "X", "misc", 10)])
    run.turn(run.lane("x"), "ls")
    return run.close().dir


@needs_permissions
def test_report_on_a_run_with_a_file_it_cannot_read_fails_with_the_reason(tmp_path):
    transcript = small_run(tmp_path) / "lanes" / "L01.jsonl"
    transcript.chmod(0)
    try:
        result = runner.invoke(mounted(), ["report", str(tmp_path)])
    finally:
        transcript.chmod(0o644)
    assert result.exit_code == 2, result.output
    assert f"flightdeck: cannot read {transcript}: Permission denied" in result.output
    assert not (tmp_path / "report.md").exists()


def test_report_on_a_run_whose_transcript_has_a_count_that_is_not_finite_names_it(tmp_path):
    rewrite(small_run(tmp_path) / "lanes" / "L01.jsonl", lambda line: {**line, "turns": float("nan")} if "lane" in line else line)
    result = runner.invoke(mounted(), ["report", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "L01.jsonl: header turns: is not a usable number; read as 0" in (tmp_path / "report.md").read_text()


@needs_permissions
def test_report_with_a_board_it_cannot_search_fails_with_the_reason(played):
    _, record = played
    board = board_dir(record)
    board.chmod(0o600)  # it can be listed, but nothing in it can be opened
    try:
        result = runner.invoke(mounted(), ["report", str(record.dir), "--board", str(board)])
    finally:
        board.chmod(0o755)
    assert result.exit_code == 2, result.output
    assert f"flightdeck: --board: {board}: cannot read it (Permission denied)" in result.output
    assert not (record.dir / "report.md").exists()
