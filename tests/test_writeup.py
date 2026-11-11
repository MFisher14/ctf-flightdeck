"""Writeup drafts, from real run folders.

Every run here is made by a real Deck (with a recording driver: the test reports each step,
as a lane would), its EventLog and its TranscriptLog in tmp_path, then read back with
runrecord.load_run. File changes come from the real workspace snapshots and diffs
(agent.workspace.changed_files), so the drafts parse exactly what a run writes.

Drafts are parsed as Markdown with markdown-it (CommonMark plus GFM tables, strikethrough and
autolinks) to check that nothing from the run acts as markup: no HTML, no link, no block that
ends early.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from ctf_flightdeck import writeup
from ctf_flightdeck.agent.client import ModelClient, ModelError
from ctf_flightdeck.agent.workspace import changed_files, take_snapshot
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Challenge, DeckConfig, FileChange
from ctf_flightdeck.eventlog import EventLog
from ctf_flightdeck.mock.world import ManualClock
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.runrecord import RunRecord, load_run
from ctf_flightdeck.text import untrusted
from ctf_flightdeck.transcript import TranscriptLog
from fake_model import FakeModelServer, error_reply, text_reply

FLAG_FORMAT = r"t\{[^{}\s]+\}"
ALPHA = "t{alpha}"
SOLVE = "import base64\n# prints the flag\nprint(base64.b64decode(open('note.txt').read()).decode())\n"
TOKEN = re.compile(r"\{\{[0-9a-f]{8}-(?:block-)?\d+\}\}")


# ---------------------------------------------------------------------- building real runs


class RecordingDriver:
    """Notes what the deck asked of it and does no lane work: the test reports each step."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *args, **kwargs: self.calls.append((name, *args))


class Run:
    """A deck, its event log and its lane transcripts, in one run folder."""

    def __init__(self, folder: Path, challenges: list[Challenge], *, answers: dict[str, str],
                 models: tuple[str, ...] = ("small", "mid"), submit: str = "confirm") -> None:
        self.folder = folder
        self.clock = ManualClock(0.0)
        self.driver = RecordingDriver()
        verify = lambda cid, flag: (answers[cid] == flag) if cid in answers else None  # noqa: E731
        config = DeckConfig(event="test", flag_format=FLAG_FORMAT, submit=submit, models=models)
        self.deck = Deck(config, self.driver, self.clock, verify)
        self.log = EventLog(folder / "events.jsonl")
        self.log.attach(self.deck)
        self.transcripts = TranscriptLog(folder / "lanes")
        self.transcripts.attach(self.deck)
        self.deck.release(challenges, [QueueEntry(c.id, models[0]) for c in challenges])

    def lane(self, cid: str) -> str:
        return self.deck.lanes_on(cid)[-1].id

    def step(self, lane: str, action: str, output: str = "", *, after: float = 30.0, **report) -> None:
        self.clock.advance(after)
        report.setdefault("tokens", 100)
        self.deck.report(lane, TurnReport(action=action, output=output, **report))

    def apply(self, intervention) -> None:
        self.clock.advance(5.0)
        assert self.deck.apply(intervention).ok

    def close(self) -> RunRecord:
        self.transcripts.close()
        self.log.close()
        return load_run(self.folder)


def change(workspace: Path, path: str, content: str | bytes | None) -> FileChange:
    """What the agent driver reports when a turn writes `content` to `path` (None: deletes it):
    the real snapshot diff of the lane's workspace."""
    workspace.mkdir(parents=True, exist_ok=True)
    before = take_snapshot(workspace)
    target = workspace / path
    if content is None:
        target.unlink()
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    (changed,) = changed_files(before, take_snapshot(workspace), workspace)
    return changed


def alpha_run(tmp_path: Path) -> RunRecord:
    """Alpha solved by L01 in 12 turns (a plan, steps, a solver it wrote and ran, a hint and a
    redirect, an approved flag); Beta given up on."""
    run = Run(tmp_path / "run", [Challenge("a", "Alpha", "misc", 50, solves=3), Challenge("b", "Beta", "web", 100)],
              answers={"a": ALPHA, "b": "t{beta}"})
    a, b = run.lane("a"), run.lane("b")
    run.step(a, "plan: read the note, then decode it", plan="read the note, then decode it")  # turn 1
    run.step(a, "$ ls", "note.txt")  # turn 2
    for n in range(3, 10):  # turns 3 to 9
        run.step(a, f"$ echo step {n}", f"step {n}")
    run.apply(iv.Hint(a, "look closer at the note"))
    run.apply(iv.Redirect(a, "xor it with the key in the note"))
    run.step(a, "$ cat > solve.py <<'EOF'", files=(change(tmp_path / "work", "solve.py", SOLVE),))  # turn 10
    run.step(a, "$ python3 solve.py", f"decoding\n{ALPHA}")  # turn 11
    run.step(a, f"submit {ALPHA}", "solve.py printed it", flag=ALPHA)  # turn 12
    run.apply(iv.Approve(a))
    run.step(b, "$ curl http://127.0.0.1:8080/", "nothing", gave_up="no idea")
    return run.close()


def lines_of(markdown: str, heading: str) -> list[str]:
    """The lines of one ## section."""
    lines = markdown.split("\n")
    start = lines.index(heading)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start + 1:end]


@pytest.fixture
def markdown_it():
    module = pytest.importorskip("markdown_it", reason="markdown-it-py (a dependency of rich) is not installed")
    pytest.importorskip("linkify_it", reason="linkify-it-py is not installed, so autolinks cannot be checked")
    return module.MarkdownIt("gfm-like")


ALLOWED_TAGS = {"h1", "h2", "h3", "p", "ul", "ol", "li", "pre", "code"}


def tags(html: str) -> set[str]:
    return {name for name in re.findall(r"</?([a-zA-Z][a-zA-Z0-9]*)", html)}


# ---------------------------------------------------------------------- a lane's solve


def test_solves_are_the_accepted_flags_in_the_order_they_came(tmp_path):
    record = alpha_run(tmp_path)
    solved = writeup.solves(record)
    assert list(solved) == ["a"]  # Beta was given up on
    alpha = solved["a"]
    assert (alpha.flag, alpha.lane, alpha.judged_by, alpha.l1) == (ALPHA, "L01", "platform", None)
    assert alpha.at == record.of("submit")[0].at


def test_a_lane_solve_opens_with_the_challenge_and_how_it_went(tmp_path):
    record = alpha_run(tmp_path)
    text = writeup.draft(record, "a")
    assert text.startswith("# Alpha\n")
    head = text.split("\n## ")[0]
    assert "- Category: misc" in head and "- Points: 50" in head
    assert "- Solved by: lane L01 at T+00:06:15, 6m after it started" in head
    assert "- Model: small" in head
    assert "- Spent: 12 turns, 1k tokens, $0.00" in head
    assert "- Started as: a fresh lane from the queue" in head
    assert "Beta" not in text and "L02" not in text  # another challenge's lane is no part of it


def test_the_approach_is_the_plan_changes_in_order(tmp_path):
    text = writeup.draft(alpha_run(tmp_path), "a")
    assert [line for line in lines_of(text, "## Approach") if line] == [
        "1. Turn 1, the lane's plan: read the note, then decode it",
        "2. Turn 9, you redirected it: xor it with the key in the note",
    ]


def test_the_steps_that_mattered_are_the_one_whose_output_held_the_flag_and_the_five_before(tmp_path):
    text = writeup.draft(alpha_run(tmp_path), "a")
    section = lines_of(text, "## Steps that mattered")
    assert section[1] == "The flag first shows in the output of turn 11. Here it is with the 5 steps before it."
    headings = [line for line in section if line.startswith("### ")]
    assert headings == [f"### Turn {n}" for n in range(6, 11)] + ["### Turn 11 (the flag shows here)"]
    key = section.index("### Turn 11 (the flag shows here)")
    assert section[key + 2] == "`$ python3 solve.py`"
    assert section[key + 4: key + 8] == ["```text", "decoding", ALPHA, "```"]
    turn10 = section.index("### Turn 10")
    assert section[turn10 + 2: turn10 + 5] == ["`$ cat > solve.py <<'EOF'`", "", "No output recorded."]


def test_the_files_the_lane_wrote_are_shown_whole(tmp_path):
    text = writeup.draft(alpha_run(tmp_path), "a")
    section = lines_of(text, "## Files the lane wrote")
    at = section.index("### `solve.py`, added in turn 10, 3 lines")
    assert "\n".join(section[at + 2: at + 7]) == "```python\n" + SOLVE + "```"


def test_the_players_interventions_are_listed_with_their_turns(tmp_path):
    text = writeup.draft(alpha_run(tmp_path), "a")
    assert [line for line in lines_of(text, "## Your interventions") if line] == [
        "- Turn 9, hint: look closer at the note",
        "- Turn 9, redirect: xor it with the key in the note",
        f"- Turn 12, approval: `submit {ALPHA}`",
    ]


def test_the_flag_is_shown_with_who_said_it_was_right(tmp_path):
    text = writeup.draft(alpha_run(tmp_path), "a")
    assert [line for line in lines_of(text, "## Flag") if line] == [
        "```text", ALPHA, "```", "Accepted at T+00:06:15 on lane L01: the board checked it.",
    ]


def test_a_challenge_the_run_did_not_solve_has_no_draft(tmp_path):
    record = alpha_run(tmp_path)
    with pytest.raises(writeup.WriteupError, match="'b' has no accepted flag in this run"):
        writeup.draft(record, "b")
    with pytest.raises(writeup.WriteupError, match="'zz' is not in this run"):
        writeup.draft(record, "zz")


def test_a_lane_with_no_interventions_and_no_plan_says_so(tmp_path):
    run = Run(tmp_path / "run", [Challenge("q", "Quick", "misc", 10)], answers={"q": "t{q}"}, submit="auto")
    q = run.lane("q")
    run.step(q, "$ cat flag.txt", "t{q}", flag="t{q}")  # auto submit: no approval asked
    text = writeup.draft(run.close(), "q")
    assert lines_of(text, "## Approach")[1] == "The lane recorded no plan."
    assert lines_of(text, "## Your interventions")[1] == "None: the lane worked on its own."
    assert lines_of(text, "## Files the lane wrote")[1] == "None: the lane changed no files in its workspace."
    assert "The flag first shows in the output of turn 1." in text and "steps before it" not in text


def test_a_plan_set_beside_other_work_is_still_named_as_the_last_plan(tmp_path):
    run = Run(tmp_path / "run", [Challenge("p", "Plans", "misc", 10)], answers={"p": "t{p}"})
    p = run.lane("p")
    run.step(p, "plan: look around", plan="look around")
    run.step(p, "$ ls  (+1 more)", "x.bin", plan="carve the zip out of x.bin")  # the plan is not in the step
    run.step(p, "submit t{p}", flag="t{p}")
    run.apply(iv.Approve(p))
    items = [line for line in lines_of(writeup.draft(run.close(), "p"), "## Approach") if line]
    assert items == [
        "1. Turn 1, the lane's plan: look around",
        "2. Its plan at the end, set in a turn that also did other work (so the log does not say when): "
        "`carve the zip out of x.bin`",
    ]


def test_a_redirect_that_is_the_last_plan_is_not_listed_twice(tmp_path):
    run = Run(tmp_path / "run", [Challenge("r", "Redirected", "misc", 10)], answers={"r": "t{r}"})
    r = run.lane("r")
    run.step(r, "$ ls", "a")
    run.apply(iv.Redirect(r, "try rot13"))
    run.step(r, "submit t{r}", flag="t{r}")
    run.apply(iv.Approve(r))
    items = [line for line in lines_of(writeup.draft(run.close(), "r"), "## Approach") if line]
    assert items == ["1. Turn 1, you redirected it: try rot13"]


# ---------------------------------------------------------------------- which steps mattered


def test_with_no_output_holding_the_flag_the_step_that_ran_a_file_the_lane_wrote_matters(tmp_path):
    run = Run(tmp_path / "run", [Challenge("s", "Script", "rev", 100)], answers={"s": "t{s}"})
    s = run.lane("s")
    run.step(s, "$ file chall", "ELF 64-bit")
    run.step(s, "$ cat > run.sh <<'EOF'", files=(change(tmp_path / "work", "run.sh", "echo hi\n"),))
    run.step(s, "$ chmod +x run.sh && ./run.sh  (+1 more)", "hi")  # ran it (after a chmod)
    run.step(s, "$ python3 -c 'print(1)' > out.txt", files=(change(tmp_path / "work", "out.txt", "1\n"),))  # wrote it
    run.step(s, "$ cat run.sh", "echo hi")  # only shows it
    run.step(s, "read notes.txt", "1 lines")
    run.step(s, "submit t{s}", "worked it out from the output", flag="t{s}")
    run.apply(iv.Approve(s))
    section = lines_of(writeup.draft(run.close(), "s"), "## Steps that mattered")
    assert section[1] == ("No step's output shows the flag; the last step that ran a file the lane wrote is turn 3, "
                          "which ran `run.sh`. Here it is with the 2 steps before it.")
    assert [line for line in section if line.startswith("### ")] == [
        "### Turn 1", "### Turn 2", "### Turn 3 (this ran a file the lane wrote)",
    ]


def test_with_neither_the_last_step_before_the_flag_matters_and_the_draft_says_why(tmp_path):
    run = Run(tmp_path / "run", [Challenge("n", "Neither", "misc", 10)], answers={"n": "t{n}"})
    n = run.lane("n")
    for k in range(1, 9):
        run.step(n, f"$ echo {k}", str(k))
    run.step(n, "submit t{n}", "guessed", flag="t{n}")
    run.apply(iv.Approve(n))
    section = lines_of(writeup.draft(run.close(), "n"), "## Steps that mattered")
    assert section[1] == ("No step's output shows the flag and no step ran a file the lane wrote, so this is the last "
                          "step before the flag was accepted. Here it is with the 5 steps before it.")
    assert [line for line in section if line.startswith("### ")] == [
        "### Turn 4", "### Turn 5", "### Turn 6", "### Turn 7", "### Turn 8", "### Turn 9 (the last step)",
    ]


def test_the_flag_is_found_in_the_first_output_that_holds_it_not_a_later_one(tmp_path):
    run = Run(tmp_path / "run", [Challenge("f", "First", "misc", 10)], answers={"f": "t{f}"})
    lane = run.lane("f")
    run.step(lane, "$ ls", "solve.py")
    run.step(lane, "$ python3 solve.py", "t{f}")
    run.step(lane, "$ echo done", "done")
    run.step(lane, "submit t{f}", "solve.py printed t{f}", flag="t{f}")  # how it was found repeats it
    run.apply(iv.Approve(lane))
    section = lines_of(writeup.draft(run.close(), "f"), "## Steps that mattered")
    assert section[1] == "The flag first shows in the output of turn 2. Here it is with the 1 step before it."


def test_the_last_run_of_a_file_the_lane_wrote_is_the_one_that_mattered(tmp_path):
    run = Run(tmp_path / "run", [Challenge("r", "Rerun", "rev", 10)], answers={"r": "t{r}"})
    lane = run.lane("r")
    run.step(lane, "$ cat > solve.py <<'EOF'", files=(change(tmp_path / "work", "solve.py", "print(1)\n"),))
    run.step(lane, "$ python3 solve.py", "Traceback: KeyError")
    run.step(lane, "$ sed -i s/1/2/ solve.py", "", files=(change(tmp_path / "work", "solve.py", "print(2)\n"),))
    run.step(lane, "$ python3 solve.py", "decoded the key")
    run.step(lane, "submit t{r}", "from the key", flag="t{r}")
    run.apply(iv.Approve(lane))
    section = lines_of(writeup.draft(run.close(), "r"), "## Steps that mattered")
    assert section[1].startswith("No step's output shows the flag; the last step that ran a file the lane wrote is "
                                 "turn 4, which ran `solve.py`.")


def test_long_outputs_are_cut_to_twenty_lines_and_long_lines_short_and_the_draft_says_so(tmp_path):
    run = Run(tmp_path / "run", [Challenge("o", "Output", "misc", 10)], answers={"o": "t{o}"})
    o = run.lane("o")
    output = "t{o}\n" + "".join(f"line {k}\n" for k in range(2, 31)) + "\n\n"
    run.step(o, "$ ./dump", output)
    run.step(o, "$ ./wide", "w" * 900)
    run.step(o, "submit t{o}", flag="t{o}")
    run.apply(iv.Approve(o))
    section = lines_of(writeup.draft(run.close(), "o"), "## Steps that mattered")
    start = section.index("```text")
    end = section.index("```", start + 1)
    assert section[start + 1: end] == ["t{o}"] + [f"line {k}" for k in range(2, 21)]
    assert section[end + 2] == "Output cut: the first 20 of its 30 lines are shown."
    assert "w" * 901 not in "\n".join(section)  # turn 2 is after the step that mattered: not shown at all


def test_a_line_over_the_limit_is_cut_and_the_draft_says_so(tmp_path):
    run = Run(tmp_path / "run", [Challenge("w", "Wide", "misc", 10)], answers={"w": "t{w}"})
    w = run.lane("w")
    run.step(w, "$ ./wide", "w" * 900 + "\nt{w}")
    run.step(w, "submit t{w}", flag="t{w}")
    run.apply(iv.Approve(w))
    section = lines_of(writeup.draft(run.close(), "w"), "## Steps that mattered")
    start = section.index("```text")
    assert section[start + 1: start + 4] == ["w" * writeup.LINE_CHARS, "t{w}", "```"]
    assert section[start + 5] == f"Output cut: lines over {writeup.LINE_CHARS} characters are cut short."


# ---------------------------------------------------------------------- files


@pytest.mark.parametrize(
    "content",
    ["one line\n", "no newline at the end", "", "++ looks like a header\n@@ -1 +1 @@ too\n--- and this\n",
     "\n\n\nblank lines\n\n", "crlf\r\nline\r\n", "tab\tand unicode: café\n"],
)
def test_an_added_files_content_comes_back_whole_from_its_real_diff(tmp_path, content):
    added = change(tmp_path / "work", "f.txt", content)
    assert added.status == "added"
    assert writeup.added_content(added.diff) == content


def test_a_diff_that_is_not_an_added_text_file_gives_no_content(tmp_path):
    work = tmp_path / "work"
    assert writeup.added_content(change(work, "x.bin", b"\x00\x01\x02\x03").diff) is None  # "binary file, 4 bytes"
    change(work, "y.txt", "old\n")
    assert writeup.added_content(change(work, "y.txt", "new\n").diff) is None  # modified, not added


def run_with_files(tmp_path: Path, files: list[tuple[str, str | bytes | None]], ran: str = "") -> str:
    run = Run(tmp_path / "run", [Challenge("f", "Files", "misc", 10)], answers={"f": "t{f}"})
    f = run.lane("f")
    work = tmp_path / "work"
    for path, content in files:
        run.step(f, f"$ cat > {path} <<'EOF'", files=(change(work, path, content),))
    if ran:
        run.step(f, f"$ python3 {ran}", "done")
    run.step(f, "submit t{f}", flag="t{f}")
    run.apply(iv.Approve(f))
    return writeup.draft(run.close(), "f")


def test_a_file_is_shown_whole_under_200_lines_and_named_at_200(tmp_path):
    short = "".join(f"{k}\n" for k in range(199))
    long = "".join(f"{k}\n" for k in range(200))
    text = run_with_files(tmp_path, [("short.txt", short), ("long.txt", long)])
    section = "\n".join(lines_of(text, "## Files the lane wrote"))
    assert "### `short.txt`, added in turn 1, 199 lines\n\n```text\n" + short + "```" in section
    assert ("### `long.txt`, added in turn 2, 200 lines\n\nToo long to show here (a draft shows files under 200 lines); "
            "its diff is in `lanes/L01.jsonl`.") in section
    assert "\n199\n" not in section


def test_modified_binary_and_deleted_files_are_described_not_dumped(tmp_path):
    text = run_with_files(tmp_path, [("keep.txt", "v1\n"), ("keep.txt", "v2\n"), ("blob.bin", b"\x00\xff" * 8),
                                     ("gone.txt", "x\n"), ("gone.txt", None)])
    section = "\n".join(lines_of(text, "## Files the lane wrote"))
    assert ("### `keep.txt`, modified in turn 2\n\nIts last change, as the transcript keeps it:\n\n```diff\n"
            "--- a/keep.txt\n+++ b/keep.txt\n@@ -1 +1 @@\n-v1\n+v2\n```") in section
    assert "### `blob.bin`, added in turn 3\n\nNot shown: binary file, 16 bytes." in section
    assert section.rstrip().endswith("Deleted: `gone.txt`.")


def test_files_a_step_ran_come_first_and_only_ten_are_shown_whole(tmp_path):
    files = [(f"out{k:02d}.txt", f"{k}\n") for k in range(12)] + [("solve.py", "print(1)\n")]
    section = lines_of(run_with_files(tmp_path, files, ran="solve.py"), "## Files the lane wrote")
    headings = [line for line in section if line.startswith("### ")]
    assert headings[0] == "### `solve.py`, added in turn 13, 1 line"  # the one a step ran, though written last
    assert len(headings) == writeup.WHOLE_FILES
    assert "3 more, not shown here (their diffs are in `lanes/L01.jsonl`):" in section
    assert [line for line in section if line.startswith("- ")] == [
        "- `out09.txt`, added in turn 10", "- `out10.txt`, added in turn 11", "- `out11.txt`, added in turn 12",
    ]


# ---------------------------------------------------------------------- forks, escalations, take-overs


def test_a_fork_that_solved_names_where_it_came_from_and_its_approach(tmp_path):
    run = Run(tmp_path / "run", [Challenge("c", "Gamma", "cry", 200)], answers={"c": "t{gamma}"})
    first = run.lane("c")
    run.step(first, "plan: try a small e", plan="try a small e")
    run.step(first, "$ python3 small_e.py", "no luck")
    run.apply(iv.Fork(first, approach="try a padding oracle", model="mid"))
    fork = run.lane("c")
    assert fork != first
    run.step(fork, "$ python3 oracle.py", "t{gamma}", files=())
    run.step(fork, "submit t{gamma}", flag="t{gamma}")
    run.apply(iv.Approve(fork))
    text = writeup.draft(run.close(), "c")
    head = text.split("\n## ")[0]
    assert f"- Solved by: lane {fork} at" in head
    assert f"- Started as: your fork of lane {first}" in head
    assert "- Model: mid" in head
    assert f"- Other lanes on it: {first} (stopped): {fork} solved it" in head
    assert lines_of(text, "## Approach")[1] == f"1. You forked it from lane {first}, with the approach try a padding oracle."


def test_an_escalated_lane_names_both_models_and_a_take_over_shows_as_an_intervention(tmp_path):
    run = Run(tmp_path / "run", [Challenge("e", "Epsilon", "rev", 300)], answers={"e": "t{eps}"})
    e = run.lane("e")
    run.step(e, "$ strings chall", "nothing")
    run.apply(iv.Escalate(e))
    run.step(e, "$ objdump -d chall", "lots")
    run.apply(iv.TakeOver(e))
    run.apply(iv.HandBack(e, "ran the decoder myself"))
    run.step(e, "$ python3 decode.py", "t{eps}")
    run.step(e, "submit t{eps}", flag="t{eps}")
    run.apply(iv.Approve(e))
    text = writeup.draft(run.close(), "e")
    assert "- Model: small, then mid" in text
    assert [line for line in lines_of(text, "## Your interventions") if line] == [
        "- Turn 1, escalation: `small → mid with a summary`",
        "- Turn 2, take-over",
        "- Turn 2, hand-back: ran the decoder myself",
        "- Turn 4, approval: `submit t{eps}`",
    ]


def test_a_re_queued_attempt_says_so(tmp_path):
    run = Run(tmp_path / "run", [Challenge("k", "Kappa", "misc", 10)], answers={"k": "t{k}"})
    first = run.lane("k")
    run.step(first, "$ ls", "x")
    run.apply(iv.Kill(first, requeue=True))
    second = run.lane("k")
    run.step(second, "$ cat x", "t{k}")
    run.step(second, "submit t{k}", flag="t{k}")
    run.apply(iv.Approve(second))
    head = writeup.draft(run.close(), "k").split("\n## ")[0]
    assert "- Started as: attempt 2, after you re-queued the challenge" in head
    assert f"- Other lanes on it: {first} (killed): by the player; re-queued fresh" in head


def test_a_flag_you_confirmed_by_hand_says_you_did(tmp_path):
    run = Run(tmp_path / "run", [Challenge("h", "Hand", "misc", 10)], answers={})  # the board cannot check flags
    h = run.lane("h")
    run.step(h, "$ cat note", "t{h}")
    run.step(h, "submit t{h}", flag="t{h}")
    run.apply(iv.Approve(h))  # submit: the board cannot check it, so you submit by hand
    run.apply(iv.Approve(h))  # and say the platform accepted it
    text = writeup.draft(run.close(), "h")
    assert lines_of(text, "## Flag")[-2] == "Accepted at T+00:01:10 on lane L01: you said the platform accepted it."


# ---------------------------------------------------------------------- L1 solves


def l1_run(tmp_path: Path) -> RunRecord:
    run = Run(tmp_path / "run", [Challenge("d", "Delta", "cry", 100)], answers={"d": "t{delta}"})
    d = run.lane("d")
    run.clock.advance(1.0)
    run.deck.record_l1("d", "carve.zip", "none", seconds=1.0, notes="no archive inside", lane_id=d)
    run.deck.record_l1("d", "decode.base64", "solved", flags=["t{delta}", "t{other}"], seconds=0.4,
                       notes="base64 of a.txt, 2 layers", lane_id=d)
    run.deck.report(d, TurnReport(turn=False, flag="t{delta}"))  # L1 flags go through the lane's approval
    run.apply(iv.Approve(d))
    return run.close()


def test_an_l1_solve_names_the_engine_and_what_it_recorded(tmp_path):
    record = l1_run(tmp_path)
    solve = writeup.solves(record)["d"]
    assert solve.l1 is not None and solve.l1.engine == "decode.base64" and solve.lane == "L01"
    text = writeup.draft(record, "d")
    assert "- Solved by: the L1 engine `decode.base64`, with no model, at T+00:00:06" in text
    assert [line for line in lines_of(text, "## How L1 solved it") if line] == [
        "The L1 engine `decode.base64` found the flag with no model, in 0.4 s.",
        "- Status: solved",
        "- Flags it reported: `t{delta}`, `t{other}`",
        "- Notes: `base64 of a.txt, 2 layers`",
        "- Evidence: the run log keeps the engine's notes, not its evidence list",
        "- Reported on lane L01, where you approved it",
        "Other L1 engines that ran on it:",
        "- `carve.zip`, none: no archive inside",
    ]
    assert "## Steps that mattered" not in text and "## Approach" not in text


def test_an_l1_evidence_list_in_the_log_is_shown_item_by_item(tmp_path):
    record = l1_run(tmp_path)
    lines = (record.dir / "events.jsonl").read_text().splitlines()
    for i, line in enumerate(lines):
        event = json.loads(line)
        if event.get("kind") == "l1" and event["data"]["engine"] == "decode.base64":
            event["data"]["evidence"] = [{"kind": "decode", "detail": "two base64 layers", "path": "a.txt", "offset": 0}]
            lines[i] = json.dumps(event)
    (record.dir / "events.jsonl").write_text("\n".join(lines) + "\n")
    text = writeup.draft(load_run(record.dir), "d")
    assert "- Evidence: `decode: two base64 layers (in a.txt at offset 0)`" in text


def test_an_l1_flag_nobody_accepted_is_not_a_solve(tmp_path):
    run = Run(tmp_path / "run", [Challenge("u", "Unsure", "misc", 10)], answers={"u": "t{u}"})
    u = run.lane("u")
    run.deck.record_l1("u", "decode.rot13", "solved", flags=["t{nope}"], seconds=0.1, lane_id=u)
    run.deck.report(u, TurnReport(turn=False, flag="t{nope}"))
    run.apply(iv.Approve(u))  # wrong: the lane carries on
    assert writeup.solves(run.close()) == {}


def test_a_wrong_l1_candidate_then_a_lane_solve_is_the_lanes_solve(tmp_path):
    run = Run(tmp_path / "run", [Challenge("c", "Gamma", "cry", 100)], answers={"c": "t{right}"})
    lane = run.lane("c")
    run.deck.record_l1("c", "decode.rot13", "candidate", flags=["t{wrong}"], seconds=0.1, lane_id=lane)
    run.deck.report(lane, TurnReport(turn=False, flag="t{wrong}"))
    run.apply(iv.Approve(lane))  # the platform rejects it; the lane carries on
    run.step(lane, "$ python3 solve.py", "t{right}")
    run.step(lane, "submit t{right}", flag="t{right}")
    run.apply(iv.Approve(lane))
    record = run.close()
    assert writeup.solves(record)["c"].l1 is None
    text = writeup.draft(record, "c")
    assert f"- Solved by: lane {lane} at" in text and "## Steps that mattered" in text
    assert "with no model" not in text


# ---------------------------------------------------------------------- what the run folder lacks


def test_a_missing_transcript_is_said_and_the_board_gives_the_name(tmp_path):
    record = alpha_run(tmp_path)
    (record.dir / "lanes" / "L01.jsonl").unlink()
    (record.dir / "lanes" / "L02.jsonl").unlink()
    record = load_run(record.dir)
    text = writeup.draft(record, "a")
    assert text.startswith("# a\n") and "- Category: unknown (not in the run log)" in text
    assert "- Points: unknown (not in the run log)" in text
    assert ("The run folder has no transcript for lane L01 (`lanes/L01.jsonl` is missing or could not be read), so "
            "its approach, steps, files and your interventions are not known.") in text
    board = tmp_path / "board"
    (board / "a").mkdir(parents=True)
    (board / "a" / "challenge.json").write_text(json.dumps({"name": "Alpha (board)", "category": "Crypto", "points": 75}))
    text = writeup.draft(record, "a", board=load_board(board))
    assert text.startswith("# Alpha (board)\n") and "- Category: cry" in text and "- Points: 75" in text


def test_lines_the_run_log_lost_are_named_in_the_draft(tmp_path):
    record = alpha_run(tmp_path)
    with (record.dir / "events.jsonl").open("a") as handle:
        handle.write('{"kind": "turn", "at": 9\n')  # a crash mid-write
    text = writeup.draft(load_run(record.dir), "a")
    gaps = [line for line in lines_of(text, "## Gaps in the run log") if line]
    assert gaps[0] == "These lines of the run folder could not be read, so this draft may miss something:"
    assert len(gaps) == 2 and gaps[1].startswith("- `events.jsonl:") and "not JSON" in gaps[1]


# ---------------------------------------------------------------------- redaction


def test_redact_replaces_every_copy_of_the_flag(tmp_path):
    run = Run(tmp_path / "run", [Challenge("a", "Alpha", "misc", 50)], answers={"a": ALPHA})
    a = run.lane("a")
    run.step(a, f"plan: check whether {ALPHA} is it", plan=f"check whether {ALPHA} is it")
    run.apply(iv.Hint(a, f"is it {ALPHA}?"))
    run.step(a, "$ cat > solve.py", files=(change(tmp_path / "work", "solve.py", f"print('{ALPHA}')\n"),))
    run.step(a, f"$ grep {ALPHA} log", "x" * 497 + ALPHA)  # the flag straddles the 500-character cut
    run.step(a, f"submit {ALPHA}", f"it printed {ALPHA}", flag=ALPHA)
    run.apply(iv.Approve(a))
    record = run.close()
    plain = writeup.draft(record, "a")
    assert plain.count(ALPHA) >= 6
    redacted = writeup.draft(record, "a", redact=True)
    assert "t{a" not in redacted  # not even the part a cut would have left
    assert "```python\nprint('<flag>')\n```" in redacted
    assert lines_of(redacted, "## Flag")[1:4] == ["```text", "<flag>", "```"]
    assert "Redacted: every copy of the flag in this draft reads `<flag>`." in redacted
    assert "- Turn 1, hint: `is it <flag>?`" in redacted


def test_redact_covers_an_l1_solve_too(tmp_path):
    text = writeup.draft(l1_run(tmp_path), "d", redact=True)
    assert "t{delta}" not in text and "- Flags it reported: `<flag>`, `t{other}`" in text


# ---------------------------------------------------------------------- hostile text


HOSTILE_NAME = "<script>alert(1)</script> ``` [x](http://evil.example) &#x202e; @admin"
HOSTILE_COMMAND = "$ echo '```' && echo \"``\" | tee x # <img src=x onerror=alert(1)>"
HOSTILE_OUTPUT = (
    "\x1b[31mred\x1b[0m\r\n"
    "````\n"
    "</code></pre><script>alert(2)</script>\n"
    "[click](javascript:alert(3)) www.evil.example\n"
    "‮evil after\n"
    "~~~\n"
    "    ```python\n"
    "t{<b>`x`</b>}\n"
    "last hostile line\n"
)
HOSTILE_FLAG = "t{<b>`x`</b>}"
HOSTILE_FILE = "`````\n<iframe src=//evil.example></iframe>\n```\n# not a heading\n"


def hostile_run(tmp_path: Path) -> RunRecord:
    run = Run(tmp_path / "run", [Challenge("x", HOSTILE_NAME, "web\n# injected", 1)], answers={"x": HOSTILE_FLAG})
    x = run.lane("x")
    run.step(x, "plan: <img src=x onerror=alert(4)> **bold** _em_", plan="<img src=x onerror=alert(4)> **bold** _em_")
    run.apply(iv.Hint(x, "[link](http://evil.example) & then ![img](http://evil.example/i.png)"))
    run.step(x, "$ cat > `pwn`.md", files=(change(tmp_path / "work", "`pwn`.md", HOSTILE_FILE),))
    run.step(x, HOSTILE_COMMAND, HOSTILE_OUTPUT)
    run.step(x, f"submit {HOSTILE_FLAG}", flag=HOSTILE_FLAG)
    run.apply(iv.Approve(x))
    return run.close()


def test_hostile_text_renders_as_text_never_as_markup(tmp_path, markdown_it):
    text = writeup.draft(hostile_run(tmp_path), "x")
    assert "\x1b" not in text and "‮" not in text and " " not in text and "\r" not in text
    html = markdown_it.render(text)
    assert tags(html) <= ALLOWED_TAGS, tags(html) - ALLOWED_TAGS
    assert "href" not in html
    assert "<a " not in html and "<img" not in html and "<script" not in html and "<iframe" not in html
    heading = re.search(r"<h1>(.*?)</h1>", html, re.S).group(1)
    assert heading.startswith("<code>") and "&lt;script&gt;" in heading


def test_hostile_output_and_files_stay_inside_their_blocks(tmp_path, markdown_it):
    text = writeup.draft(hostile_run(tmp_path), "x")
    fences = [token for token in markdown_it.parse(text) if token.type == "fence"]
    output = next(f for f in fences if "red" in f.content)
    assert output.info == "text"
    assert output.content == untrusted(HOSTILE_OUTPUT.replace("\r\n", "\n"))  # whole, folded, in one block
    held = next(f for f in fences if "iframe" in f.content)
    assert (held.info, held.content) == ("text", HOSTILE_FILE)  # ".md" is not a language we name
    flag = [f for f in fences if f.content == HOSTILE_FLAG + "\n"]
    assert len(flag) == 1 and flag[0].info == "text"
    headings = [t for t in markdown_it.parse(text) if t.type == "heading_open"]
    assert len(headings) == 1 + 5 + 3  # the title, five sections, three steps or files; nothing injected


def test_hostile_values_on_one_line_keep_their_text(tmp_path, markdown_it):
    text = writeup.draft(hostile_run(tmp_path), "x")
    lines = text.split("\n")
    assert lines[2] == "- Category: `web ⏎ # injected`"
    plan = next(line for line in lines if line.startswith("1. Turn 1"))
    tokens = markdown_it.parseInline(plan)[0].children
    assert [t.type for t in tokens] == ["text", "code_inline"]
    assert tokens[1].content == "<img src=x onerror=alert(4)> **bold** _em_"


# ---------------------------------------------------------------------- the Markdown helpers themselves


NASTY = [
    "Baby RSA", "C++ (x86)", "naïve café", "100% done, isn't it?", "<script>alert(1)</script>", "`", "``x``",
    "a`b", " leading", "trailing ", "   ", "[x](http://e.example)", "![i](x.png)", "**b** _i_", "# h", "1) list",
    "- item", "+ item", "> quote", "&amp; &#x41; &#x202e;", "http://example.com", "www.example.com",
    "user@example.com", "@mention", "a | b", "~~s~~", "$x$", ":smile:", "line1\nline2", "\x1b[31mred", "tab\there",
    "‮evil", "\\`escaped", "````", "a==b", "x^2", "{attr}", "trailing backslash\\", "=", "-",
]


@pytest.mark.parametrize("value", NASTY)
def test_an_inline_value_reads_exactly_as_its_folded_text(value, markdown_it):
    rendered = writeup.inline(value)
    assert "\n" not in rendered
    children = markdown_it.parseInline(f"label {rendered}")[0].children
    assert {t.type for t in children} <= {"text", "code_inline"}, [t.type for t in children]
    assert "".join(t.content for t in children) == "label " + untrusted(value, one_line=True)
    block = markdown_it.parse(f"- {rendered}\n")  # first on a list item's line, it starts nothing either
    assert [t.type for t in block][:3] == ["bullet_list_open", "list_item_open", "paragraph_open"]
    assert "".join(t.content for t in block[3].children) == untrusted(value, one_line=True)


@pytest.mark.parametrize("value", ["www.example.com", "user@example.com", "@mention", ":smile:", "$x$", "a.b", "#1"])
def test_text_a_renderer_might_turn_into_a_link_mention_emoji_or_math_is_code(value):
    assert writeup.inline(value).startswith("`")


def test_plain_text_stays_plain():
    assert writeup.inline("Baby RSA (part 2)") == "Baby RSA (part 2)"
    assert writeup.inline("") == "(empty)" and writeup.code("") == "(empty)"


@pytest.mark.parametrize("value", NASTY + ["```\n```\n", "a\n````\nb", "\n\nx\n\n", "~~~\ncode\n~~~"])
def test_a_fenced_block_holds_exactly_its_folded_text(value, markdown_it):
    tokens = markdown_it.parse(writeup.fenced(value) + "\nafter\n")
    assert tokens[0].type == "fence" and tokens[0].info == "text"
    body = untrusted(value.replace("\r\n", "\n"))
    assert tokens[0].content == (body if body.endswith("\n") else body + "\n")
    assert tokens[1].type == "paragraph_open"  # nothing in it ran on past the block


def test_a_block_language_is_ours_never_the_runs():
    with pytest.raises(ValueError):
        writeup.fenced("x", "python onclick=1")


# ---------------------------------------------------------------------- polish


def frozen_of(request: dict) -> str:
    return request["json"]["messages"][1]["content"]


def block_keys(frozen: str) -> list[str]:
    return [line for line in frozen.split("\n") if TOKEN.fullmatch(line) and "-block-" in line]


def polish(record: RunRecord, cid: str, server: FakeModelServer, **kwargs) -> writeup.Polished:
    async def go():
        async with ModelClient(server.base_url, None, max_retries=0) as client:
            return await writeup.polish(record, cid, client=client, model="fake/model", **kwargs)

    return asyncio.run(go())


def reworded(request: dict) -> dict:
    frozen = frozen_of(request)
    text = frozen.replace("## Approach", "## How it went").replace("Here it is with", "Shown here with")
    return text_reply(text, prompt_tokens=900, completion_tokens=700, cost=0.002)


def test_polish_sends_none_of_the_runs_text_and_keeps_every_block(tmp_path, markdown_it):
    record = alpha_run(tmp_path)
    with FakeModelServer(responder=reworded) as server:
        done = polish(record, "a", server)
    (request,) = server.requests
    sent = json.dumps(request["json"])
    for secret in (ALPHA, "Alpha", "misc", "python3 solve.py", "look closer", "xor it", "b64decode", "solve.py",
                   "read the note", "L01", "small"):
        assert secret not in sent, secret
    assert request["json"]["messages"][0] == {"role": "system", "content": writeup.POLISH_INSTRUCTIONS}
    assert "tools" not in request["json"]
    plain = writeup.draft(record, "a")
    assert done.markdown == plain.replace("## Approach", "## How it went").replace("Here it is with", "Shown here with")
    assert (done.usage.total, done.usage.cost) == (1600, 0.002)
    assert tags(markdown_it.render(done.markdown)) <= ALLOWED_TAGS


def test_polish_with_redact_still_never_holds_the_flag(tmp_path):
    record = alpha_run(tmp_path)
    with FakeModelServer(responder=lambda r: text_reply(frozen_of(r))) as server:
        done = polish(record, "a", server, redact=True)
    assert ALPHA not in json.dumps(server.requests[0]["json"]) and ALPHA not in done.markdown
    assert done.markdown == writeup.draft(record, "a", redact=True)


def test_a_reply_wrapped_whole_in_one_markdown_block_is_unwrapped_then_checked(tmp_path):
    record = alpha_run(tmp_path)
    with FakeModelServer(responder=lambda r: text_reply("```markdown\n" + frozen_of(r) + "\n```\n")) as server:
        assert polish(record, "a", server).markdown == writeup.draft(record, "a")
    inside = lambda r: text_reply("```markdown\n" + frozen_of(r) + "\nRun `ls`.\n```")  # noqa: E731
    with FakeModelServer(responder=inside) as server:
        with pytest.raises(writeup.PolishError, match="backtick"):
            polish(record, "a", server)


def _swap_blocks(frozen: str) -> str:
    first, second = block_keys(frozen)[:2]
    return frozen.replace(first, "\0").replace(second, first).replace("\0", second)


@pytest.mark.parametrize(
    ("change_reply", "reason"),
    [
        (lambda f: TOKEN.sub("", f, count=1), "placeholder 1 of"),
        (lambda f: f + "\n" + TOKEN.findall(f)[0], "2 times"),
        (lambda f: f.replace("\n\n" + block_keys(f)[0] + "\n", " " + block_keys(f)[0] + "\n"), "moved a code block"),
        (_swap_blocks, "changed the order of the code blocks"),
        (lambda f: f + "\nSee {{0badbeef-99}} too.", "placeholder(s) the draft does not have"),
        (lambda f: f + "\nSee the [writeup](http://example.com).", "a square bracket"),
        (lambda f: f + "\n<b>done</b>", "HTML"),
        (lambda f: f + "\nIt was &lt;easy&gt;.", "HTML"),
        (lambda f: f + "\nRun `ls` first.", "backtick"),
        (lambda f: f + "\n~~~\nls\n~~~", "a code block"),
        (lambda f: f + "\nIt took 4242 tries.", "numbers the draft does not: 4242"),
        (lambda f: f + "\nMore on www.example.com later.", "web address"),
        (lambda f: f + "\nThanks to @someone.", "mention"),
        (lambda f: f.replace("}}", "}", 1), "placeholder"),
        (lambda f: f + "\n" + "and so on " * 2000, "characters of prose"),
        (lambda f: "  \n\n", "empty"),
    ],
)
def test_a_polished_reply_that_breaks_a_rule_is_refused(tmp_path, change_reply, reason):
    record = alpha_run(tmp_path)
    with FakeModelServer(responder=lambda r: text_reply(change_reply(frozen_of(r)), completion_tokens=33)) as server:
        with pytest.raises(writeup.PolishError, match=re.escape(reason)) as refused:
            polish(record, "a", server)
    assert refused.value.usage is not None and refused.value.usage.total == 133  # what the refused call cost


def test_a_failed_model_call_is_an_error_not_a_quiet_plain_draft(tmp_path):
    record = alpha_run(tmp_path)
    with FakeModelServer([error_reply(400, "no such model")]) as server:
        with pytest.raises(ModelError, match="no such model"):
            polish(record, "a", server)


def test_control_characters_in_a_reply_are_folded(tmp_path):
    record = alpha_run(tmp_path)
    with FakeModelServer(responder=lambda r: text_reply(frozen_of(r).replace("## Approach", "## Approach\x07"))) as server:
        done = polish(record, "a", server)
    assert "\x07" not in done.markdown and "## Approach^G" in done.markdown
