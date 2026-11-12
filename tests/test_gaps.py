"""The gap report, read from run folders that a real deck, event log and transcript log wrote.

A driver that does no work stands in for lane work; the script reports each turn. L1 results
go through the deck's own record_l1(), as M2's L1 stage logs them. The board and the L1 pack
are written into tmp_path; the pack's engines would leave a marker file if anything ever ran
or imported them, which routing must never do. What a Markdown renderer makes of the report
is checked with a CommonMark parser (markdown-it, which the console already depends on).
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
from pathlib import Path
from urllib.parse import unquote

import pytest
import typer
from markdown_it import MarkdownIt
from typer.testing import CliRunner

from ctf_flightdeck import gaps_cli
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import ME, Challenge, DeckConfig
from ctf_flightdeck.eventlog import EventLog
from ctf_flightdeck.gaps import (
    NO_L1, NO_ROUTE, GapError, L1Solve, Routed, gap_report, gaps, gaps_json, gaps_markdown, summary,
)
from ctf_flightdeck.l1.manifest import ManifestError
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.postflight import md_text
from ctf_flightdeck.runrecord import load_run, write_run_info
from ctf_flightdeck.text import MARK, untrusted
from ctf_flightdeck.transcript import TranscriptLog
from l1_kit import tree

FLAG_FORMAT = r"t\{[^{}]+\}"


class Driver:
    """Does no lane work: the script reports each turn itself."""

    def attach(self, deck):
        self.deck = deck

    def start(self, lane, challenge):
        pass

    def pause(self, lane):
        pass

    def resume(self, lane):
        pass

    def hint(self, lane, text):
        pass

    def redirect(self, lane, text):
        pass

    def escalate(self, lane, model, summary):
        pass

    def approved(self, lane, pending):
        pass

    def rejected(self, lane, flag):
        pass

    def declined(self, lane, pending):
        pass

    def stop(self, lane):
        pass


class Script:
    """A run played by script; the real deck, EventLog and TranscriptLog write its folder."""

    def __init__(self, folder: Path, *, flags=None) -> None:
        self.folder = folder
        self.clock = ManualClock(0.0)
        self.flags = dict(flags or {})
        config = DeckConfig(event="test", team=True, flag_format=FLAG_FORMAT, models=("small", "big"))
        self.deck = Deck(config, Driver(), self.clock, lambda cid, flag: self.flags.get(cid) == flag)
        self.log = EventLog(folder / "events.jsonl")
        self.log.attach(self.deck)
        self.transcripts = TranscriptLog(folder / "lanes")
        self.transcripts.attach(self.deck)

    def tick(self, seconds: float = 10.0) -> None:
        self.clock.advance(seconds)

    def release(self, challenges, queue=()) -> None:
        self.deck.release(list(challenges), [QueueEntry(cid, "small") for cid in queue], "Board")

    def lane(self, cid: str) -> str:
        (lane,) = self.deck.lanes_on(cid)
        return lane.id

    def submit(self, cid: str, flag: str) -> None:
        """The challenge's lane finds `flag` and the player approves the submit."""
        lane = self.lane(cid)
        self.tick()
        self.deck.report(lane, TurnReport(action=f"found {flag}", flag=flag))
        self.deck.apply(iv.Approve(lane))

    def l1(self, cid: str, engine: str, status: str, flags=(), notes: str = "", lane: str | None = None) -> None:
        self.tick()
        self.deck.record_l1(cid, engine, status, flags=flags, seconds=0.5, notes=notes, lane_id=lane)

    def close(self):
        self.transcripts.close()
        self.log.close()
        return load_run(self.folder)


BOARD = {  # id: name, category, points, description, handout files
    "alpha": ("Alpha", "crypto", 100, "base64 all the way down", {"note.txt": "aGVsbG8="}),
    "bravo": ("Bravo", "web", 200, "a login form", {"app.py": "print('login')\n"}),
    "charlie": ("Charlie", "rev", 300, "xor the bytes back", {"blob.bin": "\x13\x37"}),
    "delta": ("Delta", "forensics", 150, "a capture of the night", {"dump.pcap": "\xd4\xc3\xb2\xa1"}),
    "echo": ("Echo", "pwn", 250, "a stack overflow", {"vuln.c": "int main(){}\n"}),
    "foxtrot": ("Foxtrot", "misc", 50, "guess the number", {}),
    "golf": ("Golf", "misc", 75, "base64 inside a capture", {"traffic.pcap": "\xd4\xc3\xb2\xa1"}),
    "hotel": ("Hotel", "web", 100, "a static page", {"index.html": "<p>hi</p>\n"}),
    "india": ("India", "crypto", 120, "small exponent", {"out.txt": "c = 42\n"}),
}
FLAGS = {"alpha": "t{alpha}", "bravo": "t{bravo}", "charlie": "t{charlie}", "foxtrot": "t{foxtrot}", "golf": "t{golf}"}
NOT_ON_BOARD = ("india",)


def write_board(folder: Path, skip=()) -> Path:
    folder.mkdir()
    (folder / "board.json").write_text(json.dumps({"event": "Test CTF", "flag_format": FLAG_FORMAT}))
    for cid, (name, category, points, description, files) in BOARD.items():
        if cid in skip:
            continue
        (folder / cid).mkdir()
        spec = {"name": name, "category": category, "points": points, "description": description}
        (folder / cid / "challenge.json").write_text(json.dumps(spec))
        for rel, content in files.items():
            (folder / cid / rel).write_bytes(content.encode("latin-1"))
    return folder


def play(tmp_path: Path):
    """The whole board, played by script.

    alpha    L1 strings finds nothing; a lane solves it.
    bravo    L1 sqli solves it and its lane submits that flag: not a gap.
    charlie  L1 xor reports the flag as a candidate; its lane submits it and it is accepted.
    delta    L1 zsteg is blocked and strings unsure; teammate wren solves it.
    echo     no L1 run; its lane gives up.
    foxtrot  L1 guess says solved, but its flag is rejected; the lane solves it with another.
    golf     L1 oldsolver says solved with a flag never submitted; the lane's other flag is accepted.
    hotel    no L1 run; you solve it yourself.
    india    L1 rsa says solved and nothing says otherwise: not a gap.
    """
    board_dir = write_board(tmp_path / "board")
    board = load_board(board_dir)
    run = Script(tmp_path / "run", flags=FLAGS)
    run.release([item.challenge for item in board.challenges], ["alpha", "bravo", "charlie", "echo", "foxtrot", "golf"])
    run.l1("alpha", "strings", "none", notes="no printable flag")
    run.l1("bravo", "sqli", "solved", ["t{bravo}"], lane=run.lane("bravo"))
    run.l1("charlie", "xor", "candidate", ["t{charlie}"])
    run.l1("delta", "zsteg", "blocked", notes="missing tools: zsteg (not on PATH); nothing ran")
    run.l1("delta", "strings", "unsure", notes="timed out after 60s")
    run.l1("foxtrot", "guess", "solved", ["t{wrong}"])
    run.l1("golf", "oldsolver", "solved", ["t{golf-old}"])
    run.l1("india", "rsa", "solved", ["t{india}"])
    run.submit("bravo", "t{bravo}")
    run.submit("charlie", "t{charlie}")
    run.submit("alpha", "t{alpha}")
    run.tick()
    run.deck.teammate_solved("delta", "wren")
    run.tick()
    run.deck.report(run.lane("echo"), TurnReport(action="ropper", gave_up="no leak found"))
    run.submit("foxtrot", "t{wrong}")
    run.submit("foxtrot", "t{foxtrot}")
    run.submit("golf", "t{golf}")
    run.tick()
    run.deck.teammate_solved("hotel", ME)
    return board_dir, board, run.close()


@pytest.fixture
def played(tmp_path):
    return play(tmp_path)


def write_pack(pack: Path, marker: Path) -> Path:
    """Three engines. Importing or running any of them writes `marker`."""
    pack.mkdir()
    body = (
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('imported')\n\n"
        "def solve(challenge_dir):\n"
        f"    Path({str(marker)!r}).write_text('ran')\n"
    )
    for name, engine_id, route in (
        ("b64", "decode.b64", 'keywords = ["base64"]\npriority = 60'),
        ("xor", "rev.xor", 'category = ["rev"]\nkeywords = ["xor"]\npriority = 55'),
    ):
        (pack / f"{name}.py").write_text(body)
        (pack / f"{name}.manifest.toml").write_text(f'id = "{engine_id}"\nentry = "{name}.py:solve"\n\n[[routes]]\n{route}\n')
    script = pack / "carve.sh"
    script.write_text(f"#!/bin/sh\necho ran > {shlex.quote(str(marker))}\n")
    script.chmod(0o755)
    (pack / "carve.manifest.toml").write_text(
        'id = "pcap.carve"\nentry = "cli:./carve.sh"\noutput = "text"\n\n[[routes]]\nfiles = ["ext:.pcap"]\npriority = 70\n'
    )
    return pack


# ---------------------------------------------------------------------- what is a gap, and why


def summarised(found):
    return [(g.challenge, g.solved_by, g.l1, g.reason) for g in found]


def test_every_challenge_no_l1_engine_solved_is_a_gap_with_who_solved_it_and_why(played):
    _, _, record = played
    assert summarised(gaps(record)) == [
        ("alpha", "lane", (("strings", "none"),), "routed: strings none (no printable flag)"),
        ("charlie", "l1:xor", (("xor", "candidate"),),
         "routed: xor candidate (its flag was accepted, but the engine did not report it solved)"),
        ("delta", "teammate", (("zsteg", "blocked"), ("strings", "unsure")),
         "routed: zsteg blocked (missing tools: zsteg (not on PATH); nothing ran); strings unsure (timed out after 60s)"),
        ("echo", "", (), NO_ROUTE),
        ("foxtrot", "lane", (("guess", "solved"),), "routed: guess solved (its flag was rejected)"),
        ("golf", "lane", (("oldsolver", "solved"),), "routed: oldsolver solved (its flag is not the one accepted)"),
        ("hotel", "player", (), NO_ROUTE),
    ]


def test_challenges_an_l1_engine_solved_are_listed_apart_not_as_gaps(played):
    _, _, record = played
    rep = gap_report(record)
    assert rep.l1_solved == (L1Solve("bravo", "Bravo", "sqli"), L1Solve("india", "India", "rsa"))  # named by its release
    assert rep.challenges == 9 and rep.l1_runs == 8
    assert gaps(record) == list(rep.gaps)


def test_a_run_without_any_l1_results_says_l1_never_ran(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "web", 20)], ["x"])
    run.submit("x", "t{x}")
    rep = gap_report(run.close())
    assert [(g.challenge, g.solved_by, g.l1, g.reason) for g in rep.gaps] == [
        ("x", "lane", (), NO_L1), ("y", "", (), NO_L1),
    ]
    assert "- L1 results in the run: none, so L1 did not run or reached no challenge" in gaps_markdown(rep).splitlines()


@pytest.mark.parametrize("l1_first, solved_by", [(True, "l1:xor"), (False, "lane")])
def test_a_flag_is_l1s_only_when_an_l1_run_reported_it_before_it_was_accepted(tmp_path, l1_first, solved_by):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10)], ["x"])
    if l1_first:
        run.l1("x", "xor", "candidate", ["t{x}"])
    run.submit("x", "t{x}")
    if not l1_first:
        run.l1("x", "xor", "candidate", ["t{x}"])
    (gap,) = gaps(run.close())
    assert gap.solved_by == solved_by


def test_the_first_solve_in_the_log_is_who_solved_it(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 10)], ["x"])
    run.submit("x", "t{x}")
    run.tick()
    run.deck.teammate_solved("x", "wren")  # also solved, after the lane
    run.deck.teammate_solved("y", ME)
    run.tick()
    run.deck.teammate_solved("y", "wren")  # also solved, after you
    assert [(g.challenge, g.solved_by) for g in gaps(run.close())] == [("x", "lane"), ("y", "player")]


def test_a_solve_the_platform_lists_is_yours_or_your_teams_never_a_teammates(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "web", 20)])
    run.deck.platform_solved("x", "you")
    run.deck.platform_solved("y", "your team", before_run=True)
    rep = gap_report(run.close())
    assert [(g.challenge, g.solved_by) for g in rep.gaps] == [("x", "player"), ("y", "team")]
    text = gaps_markdown(rep)
    assert headings(text, "h3") == ["X (misc, 10 pts): solved by you", "Y (web, 20 pts): solved by your team, as the platform lists it"]
    assert section(text, "## At a glance")[1] == (
        "- Gaps: 2, no L1 engine solved them: 2 solved another way (lanes 0, teammates 0, you 1, "
        "your team on the platform 1, with an L1 candidate's flag 0), 0 not solved"
    )


def test_a_solved_result_counts_while_one_of_its_flags_is_not_known_wrong(tmp_path):
    run = Script(tmp_path, flags={"x": "t{x}"})
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 10)], ["x", "y"])
    run.l1("x", "early", "candidate", ["t{x}"])
    run.l1("x", "multi", "solved", ["t{nope}", "t{x}"])  # the first run that solved it names the engine
    run.l1("x", "late", "solved", ["t{x}"])
    run.l1("y", "multi", "candidate", ["t{nope}", "t{maybe}"])
    run.submit("x", "t{nope}")  # rejected; its other flag is then accepted
    run.submit("x", "t{x}")
    run.submit("y", "t{nope}")  # rejected; t{maybe} is never submitted
    rep = gap_report(run.close())
    assert rep.l1_solved == (L1Solve("x", "X", "multi"),)
    (gap,) = rep.gaps
    assert gap.reason == "routed: multi candidate (its 2 flags: 1 rejected, 1 not submitted)"


def test_a_flag_you_declined_is_known_wrong_as_the_deck_sees_it_but_a_refused_decline_is_not(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge(cid, cid.upper(), "misc", 10) for cid in ("x", "y", "z")], ["x", "y", "z"])
    x, y, z = run.lane("x"), run.lane("y"), run.lane("z")
    run.l1("x", "eng", "solved", ["t{x}"], lane=x)
    run.l1("y", "eng", "solved", ["t{y}"], lane=y)
    run.l1("z", "eng", "solved", ["t{a}", "t{b}"], lane=z)
    run.deck.report(x, TurnReport(action="the L1 flag", flag="t{x}"))
    assert run.deck.apply(iv.Decline(x)).ok
    run.deck.report(y, TurnReport(action="the L1 flag", flag="t{y}"))
    assert run.deck.apply(iv.TakeOver(y)).ok
    assert not run.deck.apply(iv.Decline(y)).ok  # refused while you have its shell: nothing declined
    run.deck.report(z, TurnReport(action="the first L1 flag", flag="t{a}"))
    run.deck.report(z, TurnReport(action="the second L1 flag", flag="t{b}"))  # waits behind t{a}
    assert run.deck.apply(iv.Decline(z)).ok and run.deck.apply(iv.Decline(z)).ok  # t{a}, then t{b}
    assert [run.deck.not_flag(cid, flag) for cid, flag in (("x", "t{x}"), ("y", "t{y}"), ("z", "t{a}"), ("z", "t{b}"))] == [
        "the player declined to submit it", None, "the player declined to submit it", "the player declined to submit it",
    ]
    rep = gap_report(run.close())
    assert rep.l1_solved == (L1Solve("y", "Y", "eng"),)
    assert [(g.challenge, g.reason) for g in rep.gaps] == [
        ("x", "routed: eng solved (you declined to submit its flag)"),
        ("z", "routed: eng solved (its 2 flags: 2 declined by you)"),
    ]


def test_a_candidate_without_a_flag_and_a_status_from_nowhere_are_said(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.l1("x", "half", "candidate")
    run.l1("x", "odd", "maybe", notes="line one\nline two")
    (gap,) = gaps(run.close())
    assert gap.l1 == (("half", "candidate"), ("odd", "maybe"))
    assert gap.reason == (
        "routed: half candidate (no flag in the log); odd maybe (not a status flightdeck knows; line one \u23ce line two)"
    )


def test_long_notes_are_cut_in_the_reason(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    run.l1("x", "chatty", "unsure", notes="n" * 500)
    (gap,) = gaps(run.close())
    assert gap.reason == "routed: chatty unsure (" + "n" * 119 + "\u2026)"


def test_ids_the_player_typed_do_not_put_a_challenge_in_the_run(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10)])
    assert not run.deck.apply(iv.Queue("no-such-challenge")).ok
    assert [g.challenge for g in gaps(run.close())] == ["x"]


def test_a_log_that_lost_its_release_line_still_names_its_challenges(tmp_path):
    run = Script(tmp_path)
    run.release([Challenge("x", "X", "misc", 10), Challenge("y", "Y", "misc", 10)], ["y"])
    run.l1("x", "strings", "none")
    record = run.close()
    path = record.dir / "events.jsonl"
    lines = [line for line in path.read_text().splitlines() if '"kind": "release"' not in line]
    path.write_text("\n".join(lines) + "\n")
    assert [g.challenge for g in gaps(load_run(record.dir))] == ["y", "x"]  # the lane started first


def test_values_of_the_wrong_type_become_unknowns_not_crashes(tmp_path):
    lines = [
        {"kind": "run-start", "wall": "w"},
        {"at": 0, "wall": "w", "kind": "release", "data": {"challenges": ["x", 7, None, "", "y"]}},
        {"at": 1, "wall": "w", "kind": "l1", "challenge": "x", "data": {"engine": 5, "status": None, "flags": "t{x}"}},
        {"at": 2, "wall": "w", "kind": "l1", "challenge": None, "data": {"engine": "lost", "status": "solved"}},
        {"at": 3, "wall": "w", "kind": "submit", "challenge": "x", "lane": "L01", "data": {"flag": 9, "correct": "yes"}},
        {"at": 4, "wall": "w", "kind": "l1", "challenge": "y", "data": {"engine": "e", "status": "solved"}},  # flags lost
        {"kind": "run-end", "wall": "w"},
    ]
    (tmp_path / "events.jsonl").write_text("".join(json.dumps(line) + "\n" for line in lines) + "{not json\n")
    rep = gap_report(load_run(tmp_path))
    assert summarised(rep.gaps) == [("x", "", (("?", "?"),), "routed: ? ? (not a status flightdeck knows)")]
    assert rep.l1_solved == (L1Solve("y", "", "e"),)  # a solved result is taken at its word
    assert rep.notes == (
        "events.jsonl:8: not JSON (Expecting property name enclosed in double quotes); skipped",
        "1 L1 result names no challenge; left out",
        "no name or points in the run for x, y (give --board to fill them in)",
    )


def test_a_run_that_did_not_close_says_so(tmp_path):
    lines = [
        {"kind": "run-start", "wall": "w"},
        {"at": 0, "wall": "w", "kind": "release", "data": {"challenges": ["x"]}},
    ]
    (tmp_path / "events.jsonl").write_text("".join(json.dumps(line) + "\n" for line in lines))
    rep = gap_report(load_run(tmp_path))
    assert rep.notes[-1] == "the run log has no run-end line: the run did not close cleanly (it crashed, or is still running)"


# ---------------------------------------------------------------------- names, points and the board


def older(folder: Path) -> Path:
    """The run folder as a format 1 log has it: no format, and no event or names in its releases."""
    path = folder / "events.jsonl"
    lines = []
    for raw in path.read_text().splitlines():
        try:
            line = json.loads(raw)
        except ValueError:  # a torn line stays as it is
            lines.append(raw)
            continue
        if line.get("kind") == "run-start":
            line.pop("format", None)
        elif line.get("kind") == "release":
            line["data"] = {k: v for k, v in line["data"].items() if k not in ("event", "board")}
        lines.append(json.dumps(line))
    path.write_text("\n".join(lines) + "\n")
    return folder


def test_the_run_log_names_every_challenge_and_the_event_without_the_board(played):
    _, _, record = played
    rep = gap_report(record)
    named = {g.challenge: (g.name, g.category, g.points) for g in rep.gaps}
    assert named["alpha"] == ("Alpha", "cry", 100)
    assert named["delta"] == ("Delta", "for", 150) and named["hotel"] == ("Hotel", "web", 100)  # no lane: their releases
    assert rep.event == "test" and rep.notes == ()  # the deck's event, as its releases recorded it
    assert gaps_markdown(rep).startswith("# Gaps: test\n")


def test_names_and_points_of_an_older_log_come_from_the_transcripts_and_the_board_fills_the_rest(played):
    _, board, record = played
    record = load_run(older(record.dir))
    without = {g.challenge: (g.name, g.category, g.points) for g in gaps(record)}
    assert without["alpha"] == ("Alpha", "cry", 100)  # its lane's transcript
    assert without["delta"] == ("", "", None) and without["hotel"] == ("", "", None)  # no lane: unknown, not zero
    assert gap_report(record).notes == ("no name or points in the run for delta, hotel, india (give --board to fill them in)",)
    assert gap_report(record).event is None
    rep = gap_report(record, board=board)
    named = {g.challenge: (g.name, g.category, g.points) for g in rep.gaps}
    assert named["delta"] == ("Delta", "for", 150) and named["hotel"] == ("Hotel", "web", 100)
    assert rep.event == "Test CTF" and rep.notes == ()
    assert gaps_markdown(rep).startswith("# Gaps: Test CTF\n")


def test_a_board_without_the_runs_challenges_is_named_as_such(played, tmp_path):
    _, _, record = played
    other = tmp_path / "other"
    (other / "zulu").mkdir(parents=True)
    (other / "zulu" / "challenge.json").write_text(json.dumps({"name": "Zulu", "category": "misc", "points": 1}))
    notes = gap_report(record, board=load_board(other)).notes
    assert notes == ("the board has none of this run's challenges (is it the board this run played?)",)
    notes = gap_report(load_run(older(record.dir)), board=load_board(other)).notes
    assert notes[1] == "no name or points in the run for delta, hotel, india (and not on the board)"


# ---------------------------------------------------------------------- routing again with a pack


ROUTED_NOW = {
    "alpha": (Routed("decode.b64", 60, "keyword 'base64'"),),
    "charlie": (Routed("rev.xor", 55, "category rev, keyword 'xor'"),),
    "delta": (Routed("pcap.carve", 70, "file 'dump.pcap' (ext:.pcap)"),),
    "echo": (),
    "foxtrot": (),
    "golf": (Routed("pcap.carve", 70, "file 'traffic.pcap' (ext:.pcap)"), Routed("decode.b64", 60, "keyword 'base64'")),
    "hotel": (),
}


def test_a_pack_routes_each_gap_again_and_says_which_engines_reach_it_now(played, tmp_path):
    _, board, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    rep = gap_report(record, pack=pack, board=board)
    assert {g.challenge: g.routed for g in rep.gaps} == ROUTED_NOW
    assert rep.pack == str(pack) and rep.engines == 3
    assert "- Routed now with the pack " in gaps_markdown(rep)


def test_routing_with_a_pack_never_runs_or_imports_an_engine_and_changes_nothing(played, tmp_path):
    board_dir, board, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    before = tree(board_dir), tree(pack), tree(record.dir)
    gap_report(record, pack=pack, board=board)
    assert not (tmp_path / "marker").exists()
    assert (tree(board_dir), tree(pack), tree(record.dir)) == before


def test_a_gap_that_is_not_on_the_board_is_not_routed_and_the_report_says_so(played, tmp_path):
    _, _, record = played
    board = load_board(write_board(tmp_path / "partial", skip=("hotel", "echo")))
    rep = gap_report(record, pack=write_pack(tmp_path / "pack", tmp_path / "marker"), board=board)
    routed = {g.challenge: g.routed for g in rep.gaps}
    assert routed["hotel"] is None and routed["echo"] is None and routed["alpha"] == ROUTED_NOW["alpha"]
    assert "not routed now, since the board does not have them: echo, hotel" in rep.notes
    text = gaps_markdown(rep)
    assert "- Routed now with the pack " in text and " (3 engines): 4 of 5 gaps reach an engine, 2 not routed" in text
    assert section(text, "### Echo")[-1] == "- Routed now: not routed (see the problems below)"


def test_a_handout_that_went_away_after_the_board_was_read_is_not_routed_and_says_why(played, tmp_path):
    board_dir, board, record = played
    shutil.rmtree(board_dir / "echo")
    rep = gap_report(record, pack=write_pack(tmp_path / "pack", tmp_path / "marker"), board=board)
    assert {g.challenge: g.routed for g in rep.gaps}["echo"] is None
    assert rep.notes == (f"not routed now: echo: handout {board_dir.resolve() / 'echo'} is not a directory",)


def test_a_pack_needs_the_board_and_a_broken_pack_fails_loudly(played, tmp_path):
    _, board, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    with pytest.raises(GapError, match="needs the board the run played"):
        gap_report(record, pack=pack)
    (pack / "typo.manifest.toml").write_text('id = "typo"\nentry = "b64.py:solve"\nroutez = 1\n')
    with pytest.raises(ManifestError, match="routez: unknown key"):
        gap_report(record, pack=pack, board=board)


# ---------------------------------------------------------------------- the Markdown

PARSER = MarkdownIt("commonmark").enable(["table", "strikethrough"])
LINKIFY = MarkdownIt("gfm-like")
FORBIDDEN = {
    "html_block", "html_inline", "image", "link_open", "em_open", "strong_open", "s_open",
    "blockquote_open", "hr", "ordered_list_open", "code_block", "fence", "table_open",
}


def walk(text: str, parser: MarkdownIt = PARSER):
    for token in parser.parse(text):
        yield token
        yield from token.children or ()


def shown(inline) -> str:
    return "".join(child.content for child in inline.children if child.type in ("text", "code_inline"))


def headings(text: str, tag: str) -> list[str]:
    tokens = PARSER.parse(text)
    return [shown(tokens[i + 1]) for i, t in enumerate(tokens) if t.type == "heading_open" and t.tag == tag]


def section(text: str, start: str) -> list[str]:
    """The non-blank lines after the heading line that starts with `start`, up to the next heading."""
    lines = text.splitlines()
    begin = next(i for i, line in enumerate(lines) if line.startswith(start))
    out = []
    for line in lines[begin + 1:]:
        if line.startswith("#"):
            break
        if line.strip():
            out.append(line)
    return out


def test_the_markdown_has_a_glance_a_section_per_gap_and_the_l1_solves(played, tmp_path):
    _, board, record = played
    rep = gap_report(record, pack=write_pack(tmp_path / "pack", tmp_path / "marker"), board=board)
    text = gaps_markdown(rep)
    assert headings(text, "h1") == ["Gaps: Test CTF"]
    assert headings(text, "h2") == ["At a glance", "Gaps (7)", "Solved by L1 (2)"]
    assert headings(text, "h3") == [
        "Alpha (cry, 100 pts): solved by a lane",
        "Charlie (rev, 300 pts): solved with the flag L1 engine xor found",
        "Delta (for, 150 pts): solved by a teammate",
        "Echo (pwn, 250 pts): not solved",
        "Foxtrot (misc, 50 pts): solved by a lane",
        "Golf (misc, 75 pts): solved by a lane",
        "Hotel (web, 100 pts): solved by you",
    ]
    assert section(text, "## At a glance") == [
        "- Challenges in the run: 9, 2 solved by an L1 engine",
        "- Gaps: 7, no L1 engine solved them: 6 solved another way (lanes 3, teammates 1, you 1, "
        "with an L1 candidate's flag 1), 1 not solved",
        "- L1 results in the run: 8",
        f"- Routed now with the pack {md_text(str(tmp_path / 'pack'))} (3 engines): 4 of 7 gaps reach an engine",
    ]
    assert section(text, "### Delta") == [
        "- Id: delta",
        "- Why L1 did not solve it: routed: zsteg blocked (missing tools: zsteg (not on PATH); nothing ran); "
        "strings unsure (timed out after 60s)",
        "- Routed now: pcap.carve (priority 70: file 'dump.pcap' (ext:.pcap))",
    ]
    assert section(text, "### Golf")[-1] == (
        "- Routed now: pcap.carve (priority 70: file 'traffic.pcap' (ext:.pcap)); decode.b64 (priority 60: keyword 'base64')"
    )
    assert section(text, "### Echo")[-1] == "- Routed now: no engine in the pack"
    assert section(text, "## Solved by L1") == ["- Bravo: sqli", "- India: rsa"]
    assert "## Problems reading the run" not in text


def test_without_a_pack_there_is_no_routing_line(played):
    _, _, record = played
    text = gaps_markdown(gap_report(record))
    assert "Routed now" not in text
    assert headings(text, "h3")[-1] == "Hotel (web, 100 pts): solved by you"  # no lane: named by its release
    assert section(text, "### Hotel") == ["- Id: hotel", f"- Why L1 did not solve it: {NO_ROUTE}"]
    assert section(text, "## Solved by L1") == ["- Bravo: sqli", "- India: rsa"]
    older_text = gaps_markdown(gap_report(load_run(older(record.dir))))
    assert headings(older_text, "h3")[-1] == "hotel (category unknown, points unknown): solved by you"  # no name: its id


def test_problems_reading_the_run_are_reported(played):
    _, _, record = played
    with (record.dir / "events.jsonl").open("a") as handle:
        handle.write("{torn line\n")
    torn = len((record.dir / "events.jsonl").read_text().splitlines())
    rep = gap_report(load_run(older(record.dir)))  # an older log: it lacks names too
    assert section(gaps_markdown(rep), "## Problems reading the run") == [
        f"- events.jsonl:{torn}: not JSON (Expecting property name enclosed in double quotes); skipped",
        "- no name or points in the run for delta, hotel, india (give --board to fill them in)",
    ]
    assert summary(rep).splitlines()[-1] == "2 problems reading the run: see gaps.md"
    assert json.loads(gaps_json(rep))["notes"] == [
        f"events.jsonl:{torn}: not JSON (Expecting property name enclosed in double quotes); skipped",
        "no name or points in the run for delta, hotel, india (give --board to fill them in)",
    ]


def test_a_run_with_no_gaps_or_no_challenges_says_so(tmp_path):
    run = Script(tmp_path / "a")
    run.release([Challenge("x", "X", "misc", 10)])
    run.l1("x", "eng", "solved", ["t{x}"])
    assert section(gaps_markdown(gap_report(run.close())), "## Gaps") == [
        "None: an L1 engine solved every challenge in this run."
    ]
    empty = Script(tmp_path / "b").close()
    text = gaps_markdown(gap_report(empty))
    assert section(text, "## Gaps") == ["No challenges in this run."]
    assert section(text, "## Solved by L1") == ["None."]


def test_a_plain_list_of_gaps_renders_on_its_own(played):
    _, _, record = played
    found = gaps(record)
    text = gaps_markdown(found)
    assert headings(text, "h1") == ["Gaps: a run"]
    assert headings(text, "h2") == ["At a glance", "Gaps (7)"]
    assert section(text, "## At a glance") == [
        "- Gaps: 7, no L1 engine solved them: 6 solved another way (lanes 3, teammates 1, you 1, "
        "with an L1 candidate's flag 1), 1 not solved",
    ]
    data = json.loads(gaps_json(found))
    assert data["challenges"] is None and data["notes"] == [] and len(data["gaps"]) == 7


# ---------------------------------------------------------------------- the JSON


def test_the_json_holds_every_gap_for_build_mode(played, tmp_path):
    _, board, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    data = json.loads(gaps_json(gap_report(record, pack=pack, board=board)))
    assert {k: data[k] for k in ("schema", "run", "event", "challenges", "l1_results", "pack", "engines", "notes")} == {
        "schema": 1, "run": "run", "event": "Test CTF", "challenges": 9, "l1_results": 8, "pack": str(pack),
        "engines": 3, "notes": [],
    }
    assert data["gaps"][2] == {
        "challenge": "delta", "name": "Delta", "category": "for", "points": 150, "solved_by": "teammate",
        "l1": [{"engine": "zsteg", "status": "blocked"}, {"engine": "strings", "status": "unsure"}],
        "reason": "routed: zsteg blocked (missing tools: zsteg (not on PATH); nothing ran); strings unsure (timed out after 60s)",
        "routed": [{"engine": "pcap.carve", "priority": 70, "why": "file 'dump.pcap' (ext:.pcap)"}],
    }
    assert [g["challenge"] for g in data["gaps"]] == ["alpha", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"]
    assert data["solved_by_l1"] == [
        {"challenge": "bravo", "name": "Bravo", "engine": "sqli"}, {"challenge": "india", "name": "India", "engine": "rsa"},
    ]


def test_the_json_says_null_for_what_is_unknown_and_never_holds_a_flag(played):
    _, _, record = played
    record = load_run(older(record.dir))  # an older log: no event, and no points for a challenge no lane worked
    text = gaps_json(gap_report(record))
    data = json.loads(text)
    hotel = next(g for g in data["gaps"] if g["challenge"] == "hotel")
    assert hotel["points"] is None and hotel["routed"] is None and data["pack"] is None and data["event"] is None
    assert not re.search(r"t\{", text) and not re.search(r"t\{", gaps_markdown(gap_report(record)))


# ---------------------------------------------------------------------- hostile text

EVIL = (
    "x | <img src=x onerror=alert(1)> ![p](http://evil.example/p.png) [c](javascript:alert(1)) "
    "`t` *b* _i_ ~~s~~ $m$ &amp; \\| #h\n# Heading\x1b[31m\u202e!"
)


def evil_run(folder: Path):
    """A run where every text a challenge, an engine or the board controls is hostile."""
    run = Script(folder, flags={"e1": "t{e1}"})
    run.release(
        [Challenge(f"e{n}", EVIL + str(n), "web<b>|", 10) for n in (1, 2, 3)] + [Challenge("e`<i>|\n4", "Four", "misc", 5)],
        ["e1", "e2", "e3"],
    )
    run.l1("e1", "eng<i>|`x`", "solved", ["t{nope}"], notes=EVIL)
    run.l1("e2", EVIL, "<b>weird</b>", notes="<details>open</details> | [x](http://e) ```\n# h")
    run.l1("e`<i>|\n4", "x", "none")
    run.submit("e1", "t{nope}")
    run.submit("e1", "t{e1}")
    run.deck.report(run.lane("e3"), TurnReport(action="x", gave_up="1. not a list\n- nor this\n> nor a quote\n==="))
    return run.close()


def test_hostile_text_renders_as_itself_never_as_markup(tmp_path):
    record = evil_run(tmp_path / "run")
    board = tmp_path / "board"
    (board / "e1").mkdir(parents=True)
    (board / "board.json").write_text(json.dumps({"event": "CTF <script>x</script> [y](http://e) # z"}))
    (board / "e1" / "challenge.json").write_text(json.dumps({"name": "n", "category": "web", "points": 1}))
    text = gaps_markdown(gap_report(record, board=load_board(board)))
    assert not re.search("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", text)
    kinds = {token.type for token in walk(text)}
    assert not kinds & FORBIDDEN, kinds & FORBIDDEN
    assert all(t.markup.startswith("#") for t in walk(text) if t.type == "heading_open")  # no "===" heading
    assert all(t.level == 0 for t in walk(text) if t.type == "bullet_list_open")  # no list nested by a value
    assert headings(text, "h1") == ["Gaps: CTF <script>x</script> [y](http://e) # z"]
    assert headings(text, "h2") == ["At a glance", "Gaps (4)", "Solved by L1 (0)"]  # the run log names every challenge
    fold = untrusted(EVIL, one_line=True).strip()
    assert headings(text, "h3") == [
        f"{fold}1 (web<b>|, 10 pts): solved by a lane",
        f"{fold}2 (web<b>|, 10 pts): not solved",
        f"{fold}3 (web<b>|, 10 pts): not solved",
        "Four (misc, 5 pts): not solved",
    ]
    notes = fold[:119] + "\u2026"  # an engine's notes are cut to 120 characters
    items = [shown(t) for t in walk(text) if t.type == "inline"]
    assert f"Why L1 did not solve it: routed: eng<i>|`x` solved (its flag was rejected; {notes})" in items
    assert "Id: e`<i>| \u23ce 4" in items  # a hostile id renders as itself
    older_text = gaps_markdown(gap_report(load_run(older(tmp_path / "run")), board=load_board(board)))
    assert headings(older_text, "h3")[-1] == "e`<i>| \u23ce 4 (category unknown, points unknown): not solved"


def test_hostile_text_is_never_a_link_a_reader_could_not_see(tmp_path):
    text = gaps_markdown(gap_report(evil_run(tmp_path)))
    tokens = list(walk(text, LINKIFY))
    links = [(t.attrs.get("href"), tokens[i + 1].content) for i, t in enumerate(tokens) if t.type == "link_open"]
    assert links, "linkify should still find the bare URLs"
    for href, label in links:  # a value cut inside a URL ends in an ellipsis, which the href percent-encodes
        assert unquote(href) in (label, "http://" + label) and href.startswith(("http://", "https://")), (href, label)
    assert not any(t.type in ("image", "html_inline", "html_block") for t in tokens)


def test_the_json_keeps_hostile_ids_and_names_exact_and_is_ascii(tmp_path):
    text = gaps_json(gap_report(evil_run(tmp_path)))
    assert text.isascii()
    data = json.loads(text)
    assert [g["challenge"] for g in data["gaps"]] == ["e1", "e2", "e3", "e`<i>|\n4"]
    assert data["gaps"][0]["name"] == EVIL + "1"
    assert data["gaps"][1]["l1"] == [{"engine": EVIL, "status": "<b>weird</b>"}]
    assert "\n" not in data["gaps"][1]["reason"] and "\x1b" not in data["gaps"][1]["reason"]  # folded, made visible


def test_a_lone_surrogate_becomes_visible_so_the_report_can_be_written(tmp_path):
    run = Script(tmp_path / "run")
    run.release([Challenge("x", "bad \ud800 name", "misc", 10)], ["x"])
    run.l1("x", "eng\udc80", "none", notes="odd \udfff note")
    record = run.close()
    text = gaps_markdown(gap_report(record))
    text.encode("utf-8")  # would raise on a lone surrogate
    assert f"### bad {MARK} name (misc, 10 pts): not solved" in text.splitlines()
    # an engine's notes go through text.untrusted() first, which shows a lone surrogate as an escape
    # (here Markdown-escaped: the report shows eng\x80)
    assert "- Why L1 did not solve it: routed: eng\\\\x80 none (odd \\\\udfff note)" in text.splitlines()
    result = runner.invoke(mounted(), ["gaps", str(record.dir)])
    assert result.exit_code == 0, result.output
    assert json.loads((record.dir / "gaps.json").read_text())["gaps"][0]["name"] == "bad \ud800 name"


# ---------------------------------------------------------------------- the summary and the command


def test_the_summary_is_a_few_plain_lines(played, tmp_path):
    _, board, record = played
    assert summary(gap_report(record, board=board)) == (
        "Gaps: 7 of 9 challenges no L1 engine solved (6 solved another way, 1 not solved); L1 solved 2\n"
    )
    rep = gap_report(record, pack=write_pack(tmp_path / "pack", tmp_path / "marker"), board=board)
    assert summary(rep).splitlines()[1] == "Routed now: 4 of 7 gaps on the board reach an engine in the pack"


def mounted() -> typer.Typer:
    """The main CLI's shape: a group with a callback, the gaps app mounted with no name."""
    root = typer.Typer()

    @root.callback()
    def main() -> None:
        pass

    root.add_typer(gaps_cli.app)
    return root


runner = CliRunner()


def test_gaps_writes_both_files_and_prints_the_summary(played, tmp_path):
    board_dir, board, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    result = runner.invoke(mounted(), ["gaps", str(record.dir), "--board", str(board_dir), "--pack", str(pack)])
    assert result.exit_code == 0, result.output
    rep = gap_report(load_run(record.dir), pack=pack, board=board)
    assert (record.dir / "gaps.md").read_text(encoding="utf-8") == gaps_markdown(rep)
    assert (record.dir / "gaps.json").read_text(encoding="utf-8") == gaps_json(rep)
    assert result.stdout == summary(rep) + f"wrote {record.dir / 'gaps.md'}\nwrote {record.dir / 'gaps.json'}\n"
    assert not (tmp_path / "marker").exists()


def test_gaps_with_a_pack_but_no_board_fails_before_writing(played, tmp_path):
    _, _, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    result = runner.invoke(mounted(), ["gaps", str(record.dir), "--pack", str(pack)])
    assert result.exit_code == 2
    assert "flightdeck: --pack needs --board" in result.stderr and "(this run recorded none)" in result.stderr
    assert not (record.dir / "gaps.md").exists() and not (record.dir / "gaps.json").exists()


def test_gaps_on_a_tilde_path_for_a_user_that_does_not_exist_is_refused_without_a_traceback(played, tmp_path):
    """The command line refuses a path that is not there before gaps reads it, a ~ path for no
    user included: a usage error naming the path, never a RuntimeError from expanding it."""
    board_dir, _, record = played
    nobody = "~flightdeck-no-such-user/x"
    for args in ([nobody], [str(record.dir), "--board", nobody], [str(record.dir), "--board", str(board_dir), "--pack", nobody]):
        result = runner.invoke(mounted(), ["gaps", *args])
        assert result.exit_code == 2 and isinstance(result.exception, SystemExit), (args, result.output)
        assert "flightdeck-no-such-user" in result.stderr and "Traceback" not in result.output, args
    assert not (record.dir / "gaps.md").exists() and not (record.dir / "gaps.json").exists()


def test_gaps_takes_the_event_log_the_run_printed_and_routes_against_the_board_the_run_recorded(played, tmp_path):
    board_dir, board, record = played
    write_run_info(record.dir, board=board_dir)  # as run.py records it when the run starts
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    result = runner.invoke(mounted(), ["gaps", str(record.dir / "events.jsonl"), "--pack", str(pack)])
    assert result.exit_code == 0, result.output
    assert f"flightdeck: board: {board_dir.resolve()} (recorded by the run)" in result.stderr
    rep = gap_report(load_run(record.dir), pack=pack, board=board)
    assert (record.dir / "gaps.json").read_text(encoding="utf-8") == gaps_json(rep)
    assert {g.challenge: g.routed for g in rep.gaps} == ROUTED_NOW
    shutil.rmtree(board_dir)
    gone = runner.invoke(mounted(), ["gaps", str(record.dir), "--pack", str(pack)])
    assert gone.exit_code == 2 and "is not there any more: name it with --board" in gone.stderr
    other = runner.invoke(mounted(), ["gaps", str(record.dir / "lanes" / "L01.jsonl")])
    assert other.exit_code == 2 and "give the run folder (the one holding events.jsonl) or its events.jsonl" in other.stderr


def test_gaps_with_a_broken_pack_or_board_or_no_run_fails_with_the_reason(played, tmp_path):
    board_dir, _, record = played
    pack = write_pack(tmp_path / "pack", tmp_path / "marker")
    (pack / "typo.manifest.toml").write_text('id = "typo"\nentry = "b64.py:solve"\nroutez = 1\n')
    result = runner.invoke(mounted(), ["gaps", str(record.dir), "--board", str(board_dir), "--pack", str(pack)])
    assert result.exit_code == 2 and "flightdeck: --pack: " in result.stderr and "routez: unknown key" in result.stderr
    empty = tmp_path / "empty-board"
    empty.mkdir()
    result = runner.invoke(mounted(), ["gaps", str(record.dir), "--board", str(empty)])
    assert result.exit_code == 2 and "flightdeck: --board: " in result.stderr and "no challenge directories" in result.stderr
    result = runner.invoke(mounted(), ["gaps", str(tmp_path)])
    assert result.exit_code == 2 and "no events.jsonl (is this a flightdeck run folder?)" in result.stderr
    assert not (record.dir / "gaps.md").exists() and not (tmp_path / "gaps.md").exists()


def test_gaps_replaces_old_files_and_never_follows_a_symlink(played, tmp_path):
    _, _, record = played
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    (record.dir / "gaps.md").symlink_to(outside)
    (record.dir / "gaps.json").write_text("old")
    result = runner.invoke(mounted(), ["gaps", str(record.dir)])
    assert result.exit_code == 0, result.output
    assert outside.read_text() == "keep me"
    assert not (record.dir / "gaps.md").is_symlink()
    rep = gap_report(load_run(record.dir))
    assert (record.dir / "gaps.md").read_text(encoding="utf-8") == gaps_markdown(rep)
    assert (record.dir / "gaps.json").read_text(encoding="utf-8") == gaps_json(rep)
    assert sorted(p.name for p in record.dir.iterdir() if p.name.startswith(".")) == []  # no temporary file left


def test_gaps_that_cannot_write_says_why_and_leaves_no_temporary_file(played):
    _, _, record = played
    (record.dir / "gaps.json").mkdir()  # a folder where the JSON goes: the rename fails
    result = runner.invoke(mounted(), ["gaps", str(record.dir)])
    assert result.exit_code == 1
    assert f"flightdeck: cannot write the gap report in {record.dir}: " in result.stderr
    assert sorted(p.name for p in record.dir.iterdir() if p.name.startswith(".")) == []


def test_gaps_needs_an_existing_folder(tmp_path):
    result = runner.invoke(mounted(), ["gaps", str(tmp_path / "nope")])
    assert result.exit_code == 2
