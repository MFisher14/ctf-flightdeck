"""`flightdeck records`: the record of one solve, for an event's organisers. The runs are
played by script on the real deck, with the real event log and transcripts (test_postflight's
Script); the tests check what a record says against what the script did, and that nothing a
run holds can act as Markdown in it."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Call, Challenge, FileChange
from ctf_flightdeck.platform.manual import cannot_check
from ctf_flightdeck.runrecord import load_run
from ctf_flightdeck.solverecord import APPROVED, BY_HAND, NOT_IN_THE_LOG, ON_ITS_OWN, SolveRecordError, record, solved, who_sent
from test_postflight import Script, play

SETUP = {"runtime": "docker", "max_lanes": 8, "submit": "confirm", "lanes": "flightdeck", "ladder": ["small", "big"], "label": "Human-Led AI"}


def one() -> list[Challenge]:
    """A board of one challenge, new each time: the deck keeps a challenge's state on it."""
    return [Challenge("one", "One", "misc", 50)]


@pytest.fixture
def played(tmp_path):
    return play(tmp_path)[1]


def section(markdown: str, heading: str) -> list[str]:
    """The non-blank lines of one ## section."""
    lines = markdown.split("\n")
    start = lines.index(heading)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return [line for line in lines[start + 1:end] if line.strip()]


def bullets(markdown: str, heading: str) -> dict[str, str]:
    """The `- Key: value` lines of one ## section."""
    return dict(line[2:].split(": ", 1) for line in section(markdown, heading) if line.startswith("- ") and ": " in line)


def one_solve(folder: Path, *, submit: str = "confirm", verify=None, approve: int = 1) -> Script:
    """One challenge, one lane, one turn that claims the right flag, then `approve` approvals."""
    run = Script(folder, flags={"one": "t{one}"}, submit=submit, verify=verify)
    run.release(one())
    lane = run.lane("one")
    run.at(10)
    run.turn(lane, "cat note", flag="t{one}")
    for _ in range(approve):
        run.at(run.clock.now() + 5)
        run.do(iv.Approve(lane))
    return run


# ---------------------------------------------------------------------- which solves get a record


def test_a_record_is_for_a_flag_of_this_run_that_was_accepted(played):
    assert solved(played) == ["bravo", "alpha", "delta", "charlie"]  # in the order they were solved
    for cid, why in (("golf", "has no accepted flag in this run"),  # a teammate solved it: no flag of this run
                     ("hotel", "has no accepted flag in this run"),  # its one flag was wrong
                     ("zulu", "is not in this run")):
        with pytest.raises(SolveRecordError, match=f"challenge '{cid}' {why}: there is no solve to record"):
            record(played, cid)


# ---------------------------------------------------------------------- the solve: who, and who let the flag go


def test_a_lane_solve_names_the_lane_its_model_the_flag_and_that_the_player_approved_it(played):
    text = record(played, "alpha", setup=SETUP)
    assert text.startswith("# Solve record: Alpha\n")
    said = bullets(text, "## The solve")
    assert said["Challenge"] == "Alpha (id `alpha`, category misc, 50 points)"
    assert said["Solved"].startswith("T+00:01:10 into the run (")
    assert said["Flag"] == "`t{alpha}`"
    assert said["Credited to"] == "lane L01, on the model small"
    assert said["How the flag went to the platform"] == APPROVED == "you approved it, and flightdeck then sent it to be checked"
    assert said["Autopilot"] == "was not engaged in this run"
    assert said["Setup"] == "flightdeck's own lanes; models small then big; lanes ran in docker; submit policy confirm when the run started"


def test_a_flag_that_went_out_on_its_own_under_submit_auto_is_said_to_have_had_nobodys_approval(tmp_path):
    run = one_solve(tmp_path, submit="auto", approve=0)
    assert run.deck.challenges["one"].status.value == "solved"  # the claimed flag went straight to the board's verifier
    text = record(run.close(), "one")
    assert bullets(text, "## The solve")["How the flag went to the platform"] == ON_ITS_OWN
    assert "nobody approved it" in ON_ITS_OWN and "submit auto" in ON_ITS_OWN
    assert bullets(text, "## Who did what on this challenge")["You"] == "no interventions"


def test_a_flag_the_player_submitted_by_hand_is_said_to_be_the_players_own_submit(tmp_path):
    run = one_solve(tmp_path, verify=cannot_check, approve=2)  # yes to the flag, then yes: the platform accepted it
    text = record(run.close(), "one")
    assert bullets(text, "## The solve")["How the flag went to the platform"] == BY_HAND
    (line,) = [line for line in section(text, "## Flags sent for this challenge") if line.startswith("- ")]
    assert line == f"- T+00:00:20 · lane L01 · `t{{one}}` · accepted by your word · {BY_HAND}"


def test_the_deck_records_on_each_submit_whether_the_player_approved_it(tmp_path):
    def submits(run: Script) -> list[dict]:
        run.close()
        events = [json.loads(line) for line in (run.folder / "events.jsonl").read_text().splitlines()]
        return [event["data"] for event in events if event["kind"] == "submit"]

    (yes,) = submits(one_solve(tmp_path / "confirm"))
    assert (yes["by"], yes["approved"], yes["correct"]) == ("platform", True, True)
    (auto,) = submits(one_solve(tmp_path / "auto", submit="auto", approve=0))
    assert (auto["by"], auto["approved"], auto["correct"]) == ("platform", False, True)
    (hand,) = submits(one_solve(tmp_path / "hand", verify=cannot_check, approve=2))
    assert hand["by"] == "player" and "approved" not in hand  # the player's own submit: flightdeck sent nothing


def test_a_log_from_before_submits_recorded_the_approval_is_said_not_to_say(tmp_path):
    run = one_solve(tmp_path)
    run.close()
    log = tmp_path / "events.jsonl"
    older = []
    for line in log.read_text().splitlines():
        event = json.loads(line)
        if event["kind"] == "submit":
            del event["data"]["approved"]
        older.append(json.dumps(event))
    log.write_text("\n".join(older) + "\n")
    said = bullets(record(load_run(tmp_path), "one"), "## The solve")["How the flag went to the platform"]
    assert said == NOT_IN_THE_LOG and "does not say" in said  # never a guess either way


@pytest.mark.parametrize(("data", "said"), [
    ({"by": "platform", "approved": True}, APPROVED),
    ({"by": "platform", "approved": False}, ON_ITS_OWN),
    ({"by": "player"}, BY_HAND),
    ({"by": "player", "approved": True}, BY_HAND),  # the player's word is the player's submit, whatever else is there
    ({"by": "platform"}, NOT_IN_THE_LOG),
    ({"by": "platform", "approved": "yes"}, NOT_IN_THE_LOG),  # a damaged log: not true, so not said to be approved
    ({}, NOT_IN_THE_LOG),
])
def test_who_sent_a_flag_is_read_from_its_submit_event_and_nowhere_else(data, said):
    assert who_sent(data) == said


def test_an_l1_solve_is_credited_to_the_no_model_solver_and_names_the_lane_it_went_through(played):
    text = record(played, "bravo")
    said = bullets(text, "## The solve")
    assert said["Credited to"] == ("the no-model solver sqli (L1), which reported the flag before it was accepted, and went to "
                                   "the platform through lane L08")
    assert said["How the flag went to the platform"] == APPROVED
    (run,) = [line for line in section(text, "## No-model solvers (L1) on this challenge") if line.startswith("- ")]
    assert run == "- T+00:00:00 · engine sqli · status solved · on lane L08 · flags reported: `t{bravo}`"
    counts = bullets(text, "## Who did what on this challenge")
    assert counts["No-model solvers (L1)"] == "1 run"
    assert counts["Lanes (AI agents)"].startswith("1 lane, 0 turns in all")  # the lane took no model turn


# ---------------------------------------------------------------------- the declared label


def test_the_record_shows_the_declared_label_and_that_flightdeck_did_not_check_it(played):
    assert bullets(record(played, "alpha", setup=SETUP), "## The solve")["Declared label"] == (
        "Human-Led AI (the team's word to the event; flightdeck does not check it)")
    none = bullets(record(played, "alpha", setup=dict(SETUP, label="")), "## The solve")["Declared label"]
    assert none.startswith("none (")
    assert bullets(record(played, "alpha"), "## The solve")["Declared label"] == "not recorded (the run folder has no setup.json)"
    planted = record(played, "alpha", setup=dict(SETUP, label="No AI\n\n# Verified by the organisers"))
    assert bullets(planted, "## The solve")["Declared label"] == "not shown (what the run folder holds for it is not a label)"
    assert "Verified by the organisers" not in planted


# ---------------------------------------------------------------------- the interventions


def test_every_intervention_on_the_challenge_is_listed_with_its_words_and_what_came_of_it(played):
    text = record(played, "alpha")
    mine = [line for line in section(text, "## Your interventions") if line.startswith("- ")]
    assert [re.sub(r" \(`[^`]+`\)", "", line) for line in mine] == [  # without the wall-clock time of each
        "- T+00:00:50 · hint · lane L01 · took effect: L01 reads it on its next turn",
        "- T+00:01:10 · approve · lane L01 · answered the approval for submit · took effect: `t{alpha} is correct: Alpha solved by L01`",
        "- T+00:07:20 · hint · lane L01 · refused: L01 has finished (solved)",
    ]
    assert all(re.search(r" \(`\d{4}-\d\d-\d\dT[^`]+`\) · ", line) for line in mine)  # each says when, by the wall clock too
    assert "text: decode the base64" in section(text, "## Your interventions")
    assert "text: too late" in section(text, "## Your interventions")  # the refused one too: it was still the player's act
    assert bullets(text, "## Who did what on this challenge")["You"] == "3 interventions: 1 approve, 1 hint; 1 refused"
    assert "read the source first" not in text and "angr it" not in text  # other challenges' interventions are not this solve's


def test_a_fork_shows_both_lanes_whole_the_solving_one_first_and_the_fork_as_the_players_act(played):
    text = record(played, "delta")
    assert bullets(text, "## The solve")["Credited to"] == "lane L09, on the model big"
    transcripts = [line for line in text.splitlines() if line.startswith("## Transcript of lane ")]
    assert transcripts == ["## Transcript of lane L09 (the lane the accepted flag was sent on)", "## Transcript of lane L03"]
    lanes = [line for line in section(text, "## Lanes that worked this challenge") if line.startswith("- ")]
    assert lanes[0].startswith("- lane L09 · model big · started T+00:03:20 · ended T+00:04:00 · state solved · 3 turns · 6,000 tokens · "
                               "forked from lane L03 · the lane the accepted flag was sent on")
    assert lanes[1].startswith("- lane L03 · model small · started T+00:00:00 ·") and "5 turns" in lanes[1]
    for step in ("ghidra pass 1", "ghidra pass 5", "angr run 1", "angr run 3"):  # every turn of both, not the ones that mattered
        assert step in text
    assert "approach: angr it" in section(text, "## Your interventions")
    assert bullets(text, "## Who did what on this challenge")["Lanes (AI agents)"].startswith("2 lanes, 8 turns in all")


def test_a_wrong_flag_sent_for_the_challenge_is_in_its_record_beside_the_right_one(tmp_path):
    run = Script(tmp_path, flags={"one": "t{one}"})
    run.release(one())
    lane = run.lane("one")
    run.at(10)
    run.turn(lane, "strings blob", flag="t{guess}")
    run.at(20)
    run.do(iv.Approve(lane))
    run.at(30)
    run.turn(lane, "cat note", flag="t{one}")
    run.at(40)
    run.do(iv.Approve(lane))
    sent = [line for line in section(record(run.close(), "one"), "## Flags sent for this challenge") if line.startswith("- ")]
    assert sent == [
        f"- T+00:00:20 · lane L01 · `t{{guess}}` · wrong by the platform · {APPROVED}",
        f"- T+00:00:40 · lane L01 · `t{{one}}` · accepted by the platform · {APPROVED}",
    ]


# ---------------------------------------------------------------------- the transcript


def test_the_transcript_has_every_tool_call_of_a_turn_the_notes_and_the_files_with_who_changed_them(tmp_path):
    run = Script(tmp_path, flags={"one": "t{one}"})
    run.release(one())
    lane = run.lane("one")
    run.at(10)
    run.turn(lane, "ls  (+1 more)", output="note.txt", calls=(Call("ls", "note.txt\nsolve.py"), Call("python3 solve.py", "t{one}")),
             files=(FileChange("solve.py", "+print('t{one}')", "added"),), flag="t{one}", plan="read the note, then decode it")
    run.at(20)
    run.do(iv.TakeOver(lane))
    run.deck.report(lane, TurnReport(turn=False, files=(FileChange("notes.md", "+mine", "added", by="player"),)))  # as a take-over's end reports
    run.do(iv.HandBack(lane, "looked around"))
    run.at(30)
    run.do(iv.Approve(lane))
    text = record(run.close(), "one")
    body = "\n".join(section(text, "## Transcript of lane L01 (the lane the accepted flag was sent on)"))
    assert "**T+00:00:10 · turn 1 · the lane's model · step**" in body
    assert "**T+00:00:10 · turn 1 · flightdeck · alert (flag)**" in body
    assert "Tool call 1 of 2:" in body and "Tool call 2 of 2:" in body
    assert "note.txt\nsolve.py" in body and "python3 solve.py" in body  # each call with its own output, not the console's one line
    assert "read the note, then decode it" in body  # the lane's plan
    assert "· you · player**" in body and "handed back by the player: looked around" in body  # the take-over is in the lane's own log
    assert "· flightdeck · note**" in body and "submitted t{one}: correct" in body
    assert "- `solve.py` · added · turn 1 · by the lane" in body and "+print('t{one}')" in body
    assert "- `notes.md` · added · turn 1 · by you, in a take-over" in body and "+mine" in body  # yours, kept apart from the lane's


def test_a_lane_with_no_transcript_is_said_to_have_none(tmp_path):
    run = one_solve(tmp_path)
    run.close()
    (tmp_path / "lanes" / "L01.jsonl").unlink()
    text = record(load_run(tmp_path), "one")
    said = section(text, "## Transcript of lane L01 (the lane the accepted flag was sent on)")
    assert said == ["This lane has no transcript in the run folder (the run did not close cleanly?). The run log counts 1 turn for it."]


def test_a_line_of_the_run_folder_that_could_not_be_read_is_named_in_the_record(tmp_path):
    run = one_solve(tmp_path)
    run.close()
    with (tmp_path / "lanes" / "L01.jsonl").open("a") as out:
        out.write("{not json\n")
    text = record(load_run(tmp_path), "one")
    (problem,) = [line for line in section(text, "## What could not be read") if line.startswith("- ")]
    assert "L01.jsonl" in problem and "not JSON" in problem


# ---------------------------------------------------------------------- what a run holds cannot act in a record


HOSTILE = "</pre><script>alert(1)</script> [click](https://evil.example) ![x](https://evil.example/x.png)\n# Approved by the organisers\n```\n- Flag: `forged`"


def test_nothing_from_the_run_is_markup_in_a_record(tmp_path):
    markdown_it = pytest.importorskip("markdown_it", reason="markdown-it-py (a dependency of rich) is not installed")
    pytest.importorskip("linkify_it", reason="linkify-it-py is not installed, so autolinks cannot be checked")
    run = Script(tmp_path, flags={"one": "t{one}"})
    run.release([Challenge("one", HOSTILE.replace("\n", " "), "misc <b>", 50)])
    lane = run.lane("one")
    run.at(10)
    run.turn(lane, HOSTILE, output=HOSTILE, calls=(Call(HOSTILE, HOSTILE),), files=(FileChange("a`b.py", HOSTILE, "added"),),
             flag="t{one}", plan=HOSTILE)
    run.at(20)
    run.do(iv.Hint(lane, HOSTILE))
    run.at(30)
    run.do(iv.Approve(lane))
    text = record(run.close(), "one", setup=dict(SETUP, lanes=HOSTILE, ladder=[HOSTILE], runtime=HOSTILE, submit=HOSTILE, label=HOSTILE))
    tokens = markdown_it.MarkdownIt("gfm-like").parse(text)
    flat = [child for token in tokens for child in (token.children or [])] + tokens
    assert not [t for t in flat if t.type in ("html_block", "html_inline", "link_open", "image")]
    headings = [tokens[i + 1].content for i, t in enumerate(tokens) if t.type == "heading_open"]
    assert headings[0].startswith("Solve record: ") and not [h for h in headings if h.startswith("Approved")]  # the name is a code span
    assert [h.split(":")[0].split(" of lane")[0] for h in headings] == [
        "Solve record", "The solve", "Who did what on this challenge", "Flags sent for this challenge", "Your interventions",
        "Lanes that worked this challenge", "Transcript"]
    assert bullets(text, "## The solve")["Flag"] == "`t{one}`"  # the forged bullet is inside a block, not a line of ours
    assert [t.content for t in tokens if t.type == "inline" and t.content.startswith("Flag: ")] == ["Flag: `t{one}`"]
    assert sum(1 for t in tokens if t.type == "fence" and "- Flag: `forged`" in t.content) >= 5  # where the forged ones are: in blocks


def test_a_key_in_a_turns_tool_calls_or_a_diff_of_an_older_run_folder_is_not_in_the_record(tmp_path):
    """Transcripts are cleaned as they are written now; a run folder from before that still
    holds what its lanes met, in the calls and the diffs too."""
    run = one_solve(tmp_path)
    run.close()
    path = tmp_path / "lanes" / "L01.jsonl"
    key = "sk-ant-" + "a1b2c3d4" * 6
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    step = next(row for row in rows if row.get("kind") == "step")
    step["calls"] = [{"text": "env", "output": f"ANTHROPIC_API_KEY={key}\nHOME=/root"}]
    rows.append({"file": "notes.txt", "status": "added", "turn": 1, "at": 10.0, "diff": f"+Authorization: Bearer {key}"})
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    text = record(load_run(tmp_path), "one")
    assert key not in text and "a1b2c3d4" not in text
    assert "ANTHROPIC_API_KEY=[redacted]" in text and "HOME=/root" in text
    assert "t{one}" in text  # the flag is no credential


# ---------------------------------------------------------------------- the command


def invoke(*args: str):
    return CliRunner().invoke(cli.app, ["records", *args])


def test_records_writes_one_file_per_solve_in_the_run_folder_and_says_it_is_not_for_posting(tmp_path):
    play(tmp_path)
    folder = tmp_path / "run"
    result = invoke(str(folder))
    assert result.exit_code == 0, result.output
    written = sorted(path.name for path in (folder / "records").iterdir())
    assert written == ["alpha.md", "bravo.md", "charlie.md", "delta.md"]
    for name in written:
        assert f"wrote {folder / 'records' / name}" in result.output
    assert "hand it to the event's organisers only" in result.output
    assert (folder / "records" / "alpha.md").read_text() == record(load_run(folder), "alpha")  # no setup.json in a scripted run


def test_records_reads_the_label_the_run_recorded(tmp_path):
    one_solve(tmp_path).close()
    (tmp_path / "setup.json").write_text(json.dumps(SETUP))
    assert invoke(str(tmp_path)).exit_code == 0
    assert "- Declared label: Human-Led AI (the team's word to the event; flightdeck does not check it)" in (tmp_path / "records" / "one.md").read_text()


def test_records_for_one_challenge_writes_that_one_and_refuses_a_challenge_with_no_solve_before_writing(tmp_path):
    play(tmp_path)
    folder = tmp_path / "run"
    refused = invoke(str(folder), "--challenge", "alpha", "--challenge", "hotel")
    assert refused.exit_code == 2
    assert "--challenge: 'hotel' has no accepted flag in this run: there is no solve to record (solved in it: bravo, alpha, delta, charlie)" in refused.output
    assert not (folder / "records").exists()
    assert "--challenge: 'zulu' is not in this run" in invoke(str(folder), "--challenge", "zulu").output
    result = invoke(str(folder), "--challenge", "alpha")
    assert result.exit_code == 0, result.output
    assert [path.name for path in (folder / "records").iterdir()] == ["alpha.md"]


def test_a_record_that_exists_is_written_again_from_the_log_not_kept(tmp_path):
    one_solve(tmp_path).close()
    assert invoke(str(tmp_path)).exit_code == 0
    target = tmp_path / "records" / "one.md"
    honest = target.read_text()
    target.write_text(honest.replace("you approved it", "three people approved it"))
    assert invoke(str(tmp_path)).exit_code == 0
    assert target.read_text() == honest


def test_records_never_writes_through_a_symlink(tmp_path):
    one_solve(tmp_path / "run").close()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, tmp_path / "run" / "records")
    result = invoke(str(tmp_path / "run"))
    assert result.exit_code == 2 and "is a symlink; flightdeck does not write records through symlinks" in result.output
    assert list(elsewhere.iterdir()) == []
    (tmp_path / "run" / "records").unlink()
    (tmp_path / "run" / "records").mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("kept\n")
    os.symlink(outside, tmp_path / "run" / "records" / "one.md")  # a link where the record goes is replaced, never followed
    assert invoke(str(tmp_path / "run")).exit_code == 0
    assert outside.read_text() == "kept\n" and not (tmp_path / "run" / "records" / "one.md").is_symlink()


def test_a_run_with_no_accepted_flag_has_no_records_and_a_folder_that_is_no_run_fails_in_one_line(tmp_path):
    run = Script(tmp_path / "run")
    run.release(one())
    run.close()
    result = invoke(str(tmp_path / "run"))
    assert result.exit_code == 0 and "no challenge was solved with a flag of this run: no records to write" in result.output
    assert not (tmp_path / "run" / "records").exists()
    missing = invoke(str(tmp_path / "nothing"))
    assert missing.exit_code == 2 and "no such run folder" in missing.output and "Traceback" not in missing.output

