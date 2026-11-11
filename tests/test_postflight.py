"""The post-flight report, read from run folders that a real deck, event log and transcript
log wrote.

A recording driver stands in for lane work: it notes what the deck asked of it and does no
work. A manual clock moves time and the verifier knows each challenge's flag. L1 results
are lines of kind "l1" in the shape the M4 contract gives for M2's L1 stage (data: engine,
status, flags, seconds, notes), appended to the event log between deck events, since that
stage is not on this branch. What a Markdown renderer makes of the report is checked with
a CommonMark parser (markdown-it, which the console already depends on).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import typer
from markdown_it import MarkdownIt
from typer.testing import CliRunner

from ctf_flightdeck import postflight_cli
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import ME, Alert, AlertKind, Challenge, DeckConfig
from ctf_flightdeck.eventlog import EventLog
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.postflight import md_code, md_fence, md_text, report, solves, summary
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

    def __init__(self, folder: Path, *, flags=None, models=MODELS, team=True, max_lanes=8) -> None:
        self.folder = folder
        self.clock = ManualClock(0.0)
        self.driver = RecordingDriver()
        self.flags = dict(flags or {})
        self.models = models
        config = DeckConfig(event="test", team=team, max_lanes=max_lanes, flag_format=FLAG_FORMAT, models=models)
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

    def l1(self, cid: str, engine: str, status: str, flags=(), seconds=0.5, notes="") -> None:
        """An L1 engine's result, as the contract says M2's L1 stage logs one."""
        line = {
            "at": self.clock.now(), "wall": "2026-11-10T12:00:00.000+00:00", "kind": "l1",
            "text": f"L1 {engine} on {cid}: {status}", "lane": None, "challenge": cid, "alert": None,
            "data": {"engine": engine, "status": status, "flags": list(flags), "seconds": seconds, "notes": notes},
        }
        with (self.folder / "events.jsonl").open("a", encoding="ascii") as handle:
            handle.write(json.dumps(line, ensure_ascii=True) + "\n")

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
]
FLAGS = {"alpha": "t{alpha}", "charlie": "t{charlie}", "delta": "t{delta}", "hotel": "t{hotel}"}


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

    alpha    L1 strings finds nothing; L01 loops (turn 2, 20), a hint at 50, solved at 70: helped.
    bravo    L1 sqli solves it; no lane.
    charlie  L02 stalls (turn 1, 30); escalated at 500; solved 12 turns later at 1710: no effect seen.
    delta    L03 overthinks (turn 5, 105); forked at 200 to L08 on big, solved 3 turns later
             at 240: helped. L03 stops.
    echo     L04 gives up at 310.          foxtrot  L05 is killed and parked at 330.
    golf     teammate wren solves it at 350; L06 stops.
    hotel    L07's flag is wrong (410); redirected at 420, no solve; still open at the end.
    At 440 a hint to the finished L01 is refused.
    """
    board = load_board(write_board(tmp_path / "board"))
    run = Script(tmp_path / "run", flags=FLAGS)
    run.l1("alpha", "strings", "none", seconds=0.3, notes="no printable flag")
    run.l1("bravo", "sqli", "solved", ["t{bravo}"], seconds=1.2)
    run.release([b.challenge for b in board.challenges], ["alpha", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"])
    alpha, charlie, delta, echo, foxtrot, golf, hotel = (
        run.lane(cid) for cid in ("alpha", "charlie", "delta", "echo", "foxtrot", "golf", "hotel")
    )
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
        "Challenges: 8 on the board, 5 solved, 3 not solved",
        "Solves: 5 (lanes 3, L1 1, teammates 1, you 0)",
        "Points: 700 of 1150",
        "L1: 2 engine runs",
        "Lanes: 8, 30 turns",
        "Tokens: 45k (45,000), 25% cached",
        "Dollars: $0.92",
        "Cost per solve: $0.31 per lane solve ($0.92 over 3 lane solves)",
    ]


def test_without_the_board_unknown_points_are_said_not_guessed(played):
    _, record = played
    text = report(record)
    glance = items(sections(text)["At a glance"])
    assert glance[0] == "Event: not in the run log (give --board to name it)"
    assert "Points: at least 600 of at least 1050 (1 challenge with no known points)" in glance
    assert "### bravo (category unknown, points unknown): solved by L1 engine sqli" in text.splitlines()
    assert "- no name or points in the run for bravo (give --board to fill them in)" in text.splitlines()
    assert text.startswith("# Post-flight: run run\n")


def test_solves_are_credited_to_whoever_got_there_first(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}", "y": "t{y}"})
    run.l1("y", "guess", "solved", ["t{wrong}"])  # its flag is then submitted and rejected
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20), Challenge("z", "Z", "misc", 30)])
    run.turn(run.lane("y"), "try the L1 flag", flag="t{wrong}")
    run.do(iv.Approve(run.lane("y")))
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


def test_dollars_are_unknown_when_no_turn_had_a_price(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)])
    run.turn(run.lane("y"), "look", tokens=3000, dollars=None)
    run.turn(run.lane("x"), "solve", tokens=1000, dollars=None, flag="t{x}")
    run.do(iv.Approve(run.lane("x")))
    text = report(run.close())
    glance = items(sections(text)["At a glance"])
    assert "Dollars: unknown" in glance
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
    assert "- Dollars: unknown (at least $0.75; 1 of 2 lanes had no price)" in text.splitlines()
    assert "- Cost per solve: unknown (at least $0.75 per lane solve); 3k tokens per lane solve" in text.splitlines()
    small = next(row for row in table_rows(text) if row[0] == "small")
    assert small == ["small", "3", "3,000", "25%", "unknown (at least $0.75; 1 of 3 turns had no price)"]
    assert "Spend: 3k tokens (25% cached), dollars unknown (at least $0.75; 1 of 2 lanes had no price)" in summary(record)


# ---------------------------------------------------------------------- the timeline


def test_the_timeline_tells_each_challenge_in_order_with_models_and_the_solve(played):
    board, record = played
    timeline = sections(report(record, board=board), "### ")
    alpha = timeline["Alpha (misc, 50 pts): solved by lane L01"]
    assert alpha[0] == "1 lane (L01), 3 turns, 3k tokens, $0.03"
    assert entries(alpha) == [
        "released (Board)",
        "L1 strings: none in 0.3s: no printable flag",
        "L01 started on small",
        "L01 alert, Loop: the same command twice: cat note",
        "you: hint L01: decode the base64 \u2192 L01 reads it on its next turn",
        "L01 alert, Flag found: Candidate t{alpha} matches the flag format.",
        "you: approve L01 \u2192 t{alpha} is correct: Alpha solved by L01",
        "L01 submitted `t{alpha}`: correct (the solve)",
        "L01 solved after 3 turns on small (3k tokens, $0.03): solved with t{alpha}",
        "you: hint L01: too late, refused: L01 has finished (solved)",
    ]
    assert items(alpha)[0].startswith("T+00:00:00 \u00b7 ") and items(alpha)[-1].startswith("T+00:07:20 \u00b7 ")
    assert entries(timeline["Bravo (web, 100 pts): solved by L1 engine sqli"]) == [
        "released (Board)", "L1 sqli: solved in 1.2s, `t{bravo}` (the solve)",
    ]
    charlie = entries(timeline["Charlie (cry, 200 pts): solved by lane L02"])  # the board's short code
    assert charlie[-1] == "L02 solved after 13 turns on small \u2192 big (25k tokens, $0.61): solved with t{charlie}"
    assert "you: escalate L02 \u2192 Escalated L02 from small to big" in charlie
    delta = entries(timeline["Delta (rev, 300 pts): solved by lane L08"])
    assert delta[3:6] == [
        "you: fork L03: angr it \u2192 Forked L03 \u2192 L08 on big",
        "L08 started on big, a fork of L03: angr it",
        "L08 alert, Flag found: Candidate t{delta} matches the flag format.",
    ]
    assert delta[-2:] == [
        "L08 solved after 3 turns on big (6k tokens, $0.15): solved with t{delta}",
        "L03 stopped after 5 turns on small (5k tokens, $0.05): L08 solved it",
    ]
    golf = entries(timeline["Golf (misc, 50 pts): solved by teammate wren"])
    assert golf[-1] == "teammate wren solved it; flightdeck stopped L06 (the solve)"
    hotel = entries(timeline["Hotel (web, 200 pts): not solved"])
    assert hotel[3:] == [
        "you: approve L07 \u2192 t{nope} was rejected; L07 carries on",
        "L07 submitted `t{nope}`: wrong",
        "you: redirect L07: read the source first \u2192 L07 has a new plan",
    ]
    assert list(timeline)[:8] == [
        "Alpha (misc, 50 pts): solved by lane L01", "Bravo (web, 100 pts): solved by L1 engine sqli",
        "Charlie (cry, 200 pts): solved by lane L02", "Delta (rev, 300 pts): solved by lane L08",
        "Echo (pwn, 150 pts): not solved", "Foxtrot (for, 100 pts): not solved",
        "Golf (misc, 50 pts): solved by teammate wren", "Hotel (web, 200 pts): not solved",
    ]


def test_warnings_and_budget_requests_are_on_the_timeline(tmp_path):
    run = Script(tmp_path)
    run.driver.fail["y"] = "no container runtime"
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 20)], token_cap=1000)
    run.turn(run.lane("x"), "big read", tokens=1200)  # over the cap: it asks for more
    text = report(run.close())
    timeline = sections(text, "### ")
    no_lane = timeline["y (category unknown, points unknown): not solved"]  # no lane, so no name without --board
    assert entries(no_lane) == ["released (Board)", "warning: could not start a lane on Y: no container runtime"]
    x = entries(timeline["X (misc, 10 pts): not solved"])
    assert "L01 asked for approval: raise the cap by 50% (now 1k of 1k tokens)" in x
    assert "- Points: 0 of at least 10 (1 challenge with no known points)" in text.splitlines()


# ---------------------------------------------------------------------- where lanes stalled


def test_each_stall_says_when_how_it_was_answered_and_whether_the_lane_then_solved(played):
    board, record = played
    text = report(record, board=board)
    stalled = sections(text)["Where lanes stalled"]
    assert stalled[0] == (
        "3 alerts on 3 lanes: 3 answered, 1 followed by that lane solving within 10 turns. "
        "Not stalls, so only in the timeline: 4 flag found alerts, 1 teammate solved / box in use alert."
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
        "Answered: 1m later, you: fork L03: angr it \u2192 Forked L03 \u2192 L08 on big",
        "Solved within 10 turns: no, L03 did not solve it (lane L08 did)",
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


# ---------------------------------------------------------------------- interventions


def test_interventions_that_helped_and_those_with_no_effect_seen(played):
    board, record = played
    text = report(record, board=board)
    part = sections(text)["Interventions"]
    assert part[0].startswith("10 interventions, 1 refused.")
    found = sections(text, "### ")
    assert items(found["Helped (2)"]) == [
        "T+00:00:50 \u00b7 you: hint L01: decode the base64 \u2192 L01 reads it on its next turn (on Alpha); "
        "L01 solved it 1 turn and 20s later",
        "T+00:03:20 \u00b7 you: fork L03: angr it \u2192 Forked L03 \u2192 L08 on big (on Delta); L08 solved it 3 turns and 40s later",
    ]
    assert items(found["No effect seen (2)"]) == [
        "T+00:07:00 \u00b7 you: redirect L07: read the source first \u2192 L07 has a new plan (on Hotel); not solved",
        "T+00:08:20 \u00b7 you: escalate L02 \u2192 Escalated L02 from small to big (on Charlie); L02 solved it 12 turns and 20m later",
    ]
    assert found["Not judged (5)"] == ["approve 4, kill 1."]
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
        ["L08", "Delta", "big", "3", "6,000", "25%", "$0.15", "solved"],
        ["L03", "Delta", "small", "5", "5,000", "25%", "$0.05", "stopped"],
        ["L07", "Hotel", "small", "2", "2,000", "25%", "$0.04", "still open"],
        ["L01", "Alpha", "small", "3", "3,000", "25%", "$0.03", "solved"],
    ]
    assert "Ranked by dollars." in sections(text, "### ")["The 5 most expensive lanes"]


def test_tokens_counted_outside_a_turn_get_their_own_row(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.turn(run.lane("x"), "look", tokens=1000, dollars=0.1)
    run.deck.report(run.lane("x"), TurnReport(turn=False, tokens=400, dollars=0.04))  # a reply dropped on escalation
    rows = table_rows(report(run.close()))
    assert rows[1] == ["small", "1", "1,000", "25%", "$0.10"]
    assert rows[2] == ["outside a turn (a reply dropped on escalation, for one)", "-", "400", "0%", "$0.04"]


# ---------------------------------------------------------------------- lanes that gave up or were killed


def test_lanes_that_gave_up_or_were_killed_with_their_reasons(played):
    board, record = played
    part = sections(report(record, board=board))["Lanes that gave up or were killed"]
    assert items(part) == [
        "L03 on Delta was stopped at T+00:04:00 after 5 turns: L08 solved it",
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
        "28m, 8 challenges, 5 solved (lanes 3, L1 1, teammates 1, you 0), 700 of 1150 points",
        "Spend: 45k tokens (25% cached), $0.92, $0.31 per lane solve",
        "Stalls: 3 alerts, 3 answered, 1 then solved within 10 turns",
        "Interventions: 2 helped, 2 no effect seen",
        "Lanes: 8 (3 solved, 1 gave up, 1 killed, 2 stopped, 1 still open)",
    ]
    assert summary(record).splitlines()[0] == "Post-flight: event not in the run log, run run"


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
    x = entries(sections(text, "### ")["X (misc, 10 pts): solved by L1 engine 7"])
    assert x[-3:] == [
        "L1 7: solved (the solve)",  # no flags list and no number of seconds: neither is made up
        "you: hint L01: \\['a'\\] (no outcome in the log)",  # its "ok" is not true or false
        "L01 submitted `123`: no verdict",
    ]
    assert ["(none)", "1", "0", "0%", "unknown"] in table_rows(text)  # a price that is not a number is unknown, not $0


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
    """A run where every text a challenge, lane, player or engine controls is hostile."""
    run = Script(folder, flags={"e1": EVIL_FLAG}, models=("m<b>|1", "m`2`"))
    run.driver.fail["e5"] = "boom <b>|x\n# h"
    run.l1("e4", "eng<i>|`x`", "solved", ["t{<b>`|`}"], notes="<details>open</details> | [x](http://e)")
    run.release(
        [Challenge(f"e{n}", EVIL + str(n), "web<b>|", 10) for n in range(1, 6)], ["e1", "e2", "e3", "e5"],
        label="Wave <b>1</b> | x",
    )
    lane = run.lane("e1")
    run.turn(lane, EVIL_STEP, alerts=(Alert(AlertKind.LOOP, EVIL),))
    run.do(iv.Hint(lane, EVIL))
    run.do(iv.Fork(lane, EVIL))
    run.turn(lane, EVIL_STEP, flag=EVIL_FLAG)
    run.do(iv.Approve(lane))
    run.turn(run.lane("e2"), "x", gave_up="1. not a list\n- nor this\n> nor a quote\n===")
    run.deck.teammate_solved("e3", "<u>mate</u>|x")
    return run.close()


def test_hostile_text_renders_as_itself_never_as_markup(tmp_path):
    text = report(evil_run(tmp_path))
    assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", text)
    kinds = {token.type for token in walk(text)}
    assert not kinds & FORBIDDEN, kinds & FORBIDDEN
    assert all(t.markup.startswith("#") for t in walk(text) if t.type == "heading_open")  # no "===" heading
    assert all(t.level == 0 for t in walk(text) if t.type == "bullet_list_open")  # no list nested by a value
    assert headings(text, "h1") == ["Post-flight: run " + tmp_path.name]
    assert headings(text, "h2") == [
        "At a glance", "Timeline", "Where lanes stalled", "Interventions", "Spend",
        "Lanes that gave up or were killed", "Problems reading the run",
    ]
    h3 = headings(text, "h3")
    assert f"{fold(EVIL)}1 (web<b>|, 10 pts): solved by lane L01" in h3
    assert f"T+00:00:00 \u00b7 L01 on {fold(EVIL)}1: Loop" in h3
    assert all("Heading" not in h or fold(EVIL) in h for h in h3)


def test_hostile_text_keeps_to_its_table_cell(tmp_path):
    text = report(evil_run(tmp_path))
    rows = table_rows(text)
    assert ["m<b>|1", "3", "3,000", "25%", "$0.03"] in rows  # L01's two turns and L02's one
    lanes = {row[0]: row for row in rows if row[0] in ("L01", "L02", "L03", "L05")}
    assert [lanes[lane][1] for lane in ("L01", "L02", "L03", "L05")] == [fold(EVIL) + n for n in "1231"]
    assert lanes["L01"][2] == "m<b>|1" and lanes["L05"][2] == "m`2`" and lanes["L05"][7] == "stopped"


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
    assert len(lines) == 7  # title, play, spend, stalls, interventions, lanes, problems: no line of its own
    assert lines[0] == f"Post-flight: event not in the run log, run {tmp_path.name}"
    assert lines[5] == "Lanes: 4 (1 solved, 1 gave up, 2 stopped)"


def test_md_helpers_pick_fences_longer_than_any_backtick_run():
    assert md_code("plain") == "`plain`"
    assert md_code("a``b") == "```a``b```"
    assert md_code("`edge`") == "`` `edge` ``"
    assert shown(PARSER.parse(md_code("`edge`"))[1]) == "`edge`"
    assert md_fence(["x", "``` and `````"]) == ["``````text", "x", "``` and `````", "``````"]
    assert md_fence(["a\nb"]) == ["```text", "a \u23ce b", "```"]
    assert md_text("- item") == "\\- item" and md_text("1. item") == "1\\. item"
    assert md_text("a" * 300) == "a" * 199 + "\u2026"


# ---------------------------------------------------------------------- the command


def mounted() -> typer.Typer:
    """The main CLI's shape: a group with a callback, the report app mounted with no name."""
    root = typer.Typer()

    @root.callback()
    def main() -> None:
        pass

    root.add_typer(postflight_cli.app)
    return root


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


def test_report_needs_an_existing_folder(tmp_path):
    result = runner.invoke(mounted(), ["report", str(tmp_path / "nope")])
    assert result.exit_code == 2
