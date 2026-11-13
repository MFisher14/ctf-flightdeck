"""B-168: the player-notes feed (ctf/notes.py, ctf/cli/notes.py) and its push into Claude sessions
(the hooks tools/claude_launch installs). Synthetic notes only; no harness, Discord or platform."""
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ctf import cli, ledger, notes, paths

REPO = paths.repo_root()
PY = sys.executable


@pytest.fixture
def feed(tmp_path):
    return notes.Feed(tmp_path / "work" / "notes", settle=0)


def ids(items):
    return [i.id for i in items]


def run_hook_command(cmd: str, payload: dict, *, cwd: Path) -> subprocess.CompletedProcess:
    """Run a hook command the way Claude Code does: through a shell, the event JSON on stdin."""
    return subprocess.run(["/bin/sh", "-c", cmd], input=json.dumps(payload), capture_output=True,
                          text=True, timeout=60, cwd=cwd)


# ------------------------------------------------------------------------------------ delivery

def test_each_agent_gets_each_note_once(feed):
    a = feed.add("people are overthinking the crypto one")
    b = feed.add("scoreboard freezes at 18:00", kind="timing")
    assert ids(feed.pending("agent-1")) == [a.id, b.id]
    assert feed.pending("agent-1") == []                       # cursor moved
    assert ids(feed.pending("agent-2")) == [a.id, b.id]        # cursors are per agent
    c = feed.add("third")
    assert ids(feed.pending("agent-1")) == [c.id]


def test_peek_does_not_move_the_cursor(feed):
    a = feed.add("x")
    assert ids(feed.pending("p", peek=True)) == [a.id]
    assert ids(feed.pending("p", peek=True)) == [a.id]
    assert ids(feed.pending("p")) == [a.id]
    assert feed.pending("p") == []


def test_challenge_notes_reach_that_challenge_and_the_orchestrator_only(feed):
    n12 = feed.add("chal 12 was broken, re-download the zip", challenge="12", kind="fix")
    n_all = feed.add("everyone: the flag format changed", kind="ruling")
    assert ids(feed.pending("on-7", challenge="7")) == [n_all.id]
    assert ids(feed.pending("on-12", challenge="12")) == [n12.id, n_all.id]
    assert ids(feed.pending("orchestrator")) == [n12.id, n_all.id]
    # the agent on 7 skipped note 12 for good: its cursor is past it
    assert feed.pending("on-7", challenge="7") == []


def test_retraction_reaches_agents_that_saw_the_note_and_hides_it_from_the_rest(feed):
    n = feed.add("organizers say the port is 31337", challenge="5")
    assert ids(feed.pending("early", challenge="5")) == [n.id]
    r = feed.retract(n.id, reason="they corrected it")
    got = feed.pending("early", challenge="5")
    assert len(got) == 1 and isinstance(got[0], notes.Retraction)
    assert got[0].target == n.id and got[0].reason == "they corrected it"
    text = notes.render(got)
    assert "note 1 RETRACTED" in text and "port is 31337" in text and "Disregard" in text
    # an agent that never saw the note gets neither it nor the retraction
    assert feed.pending("late", challenge="5") == []
    assert feed.pending("other", challenge="6") == []
    assert feed.digest(challenge="5") == []
    assert r.id == 2 and feed.get(n.id).retracted == "they corrected it"
    with pytest.raises(notes.NotesError, match="already retracted"):
        feed.retract(n.id)
    with pytest.raises(notes.NotesError, match="no note 99"):
        feed.retract(99)


def test_retraction_of_a_challenge_note_stays_with_that_challenge(feed):
    n5 = feed.add("chal 5: the port is 31337", challenge="5")
    n_all = feed.add("everyone: hint embargo until 18:00")
    assert ids(feed.pending("on-6", challenge="6")) == [n_all.id]   # its cursor is now past note 1
    assert ids(feed.pending("on-5", challenge="5")) == [n5.id, n_all.id]
    assert feed.retract(n5.id).challenge == "5"
    assert feed.pending("on-6", challenge="6") == []
    got = feed.pending("on-5", challenge="5")
    assert [(type(i), i.target) for i in got] == [(notes.Retraction, n5.id)]


def test_digest_is_every_active_relevant_note_and_resets_the_cursor(feed):
    a = feed.add("a")
    b = feed.add("b", challenge="3")
    feed.add("c", challenge="4")
    feed.retract(a.id)
    assert ids(feed.digest("s", challenge="3")) == [b.id]
    assert feed.pending("s", challenge="3") == []              # the digest moved the cursor


def test_concurrent_writers_never_share_an_id(tmp_path):
    root = tmp_path / "notes"
    errors = []

    def writer(k):
        try:
            f = notes.Feed(root, settle=0)
            for j in range(5):
                f.add(f"w{k} n{j}")
        except Exception as e:      # surfaced by the assert below
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(k,)) for k in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert sorted(ids(notes.Feed(root).notes(sync=False))) == list(range(1, 31))


def test_bad_input_fails_with_a_named_reason(feed):
    with pytest.raises(notes.NotesError, match="unknown note kind"):
        feed.add("x", kind="gossip")
    with pytest.raises(notes.NotesError, match="empty note"):
        feed.add("   ")
    with pytest.raises(notes.NotesError, match="bad challenge id"):
        feed.add("x", challenge="../etc")
    with pytest.raises(notes.NotesError, match="empty after cleaning"):
        feed.pending("///")
    with pytest.raises(notes.NotesError, match="is not a file"):
        feed.add("x", files=[feed.root / "missing.png"])


def test_corrupt_feed_or_cursor_is_loud(feed):
    feed.add("ok")
    with open(feed.feed_path, "a") as fh:
        fh.write("{not json\n")
    with pytest.raises(notes.NotesError, match=r"feed.jsonl:2: corrupt"):
        feed.pending("x")
    feed.feed_path.write_text(json.dumps({"id": 1, "type": "note", "ts": 0, "kind": "intel", "text": "t"}) + "\n")
    (feed.root / "cursors" / "x").write_text("seven")
    with pytest.raises(notes.NotesError, match="corrupt cursor"):
        feed.pending("x")


def test_plain_words_after_bearer_are_kept(feed):
    for text in ("the bearer of bad news", "Bearer bonds. are not a hint", "bearer abc"):
        assert notes.scrub(text) == text
    for text, secret in (("bearer: shortval", "shortval"), ("Bearer=xyz", "xyz"),
                         ("Bearer eyJhbGciOi.eyJzdWIi.c2ln", "eyJhbGciOi"),
                         ("bearer " + "q" * 24, "q" * 24), ("bearer s3cr3t", "s3cr3t")):
        out = notes.scrub(text)
        assert secret not in out and "<credential removed>" in out, text
    assert feed.add("the bearer of bad news").text == "the bearer of bad news"


def test_credentials_are_removed_before_storing(feed, monkeypatch):
    monkeypatch.setenv("CTF_TOKEN", "ctfd_live_value_1234567890")
    n = feed.add("try curl -H 'Authorization: Bearer abc.def.ghi' and ctfd_live_value_1234567890, "
                 "or Authorization: Basic Zm9vOmJhcg== or bearer tok-777")
    raw = feed.feed_path.read_text()
    for secret in ("abc.def.ghi", "ctfd_live_value_1234567890", "Zm9vOmJhcg==", "tok-777"):
        assert secret not in raw and secret not in n.text
        assert secret not in feed.render_path.read_text()
    assert "<credential removed>" in n.text


def test_ledger_records_ids_never_text_and_the_alert_line_relays_the_first_line(feed):
    n = feed.add("secret-ish organizer text", challenge="9", kind="ruling")
    feed.pending("ag", challenge="9")
    feed.retract(n.id)
    recs = list(ledger.read(feed.workdir))
    kinds = [r["event"] for r in recs]
    assert kinds == ["notes.add", "notes.delivered", "notes.retract"]
    assert recs[0]["note_id"] == n.id and recs[0]["challenge_id"] == "9" and recs[0]["kind"] == "ruling"
    assert recs[1]["ids"] == [n.id] and recs[1]["agent"] == "ag"
    assert "organizer text" not in json.dumps(recs)
    log = (feed.workdir / "_logs" / "ALERTS.log").read_text().splitlines()
    assert len(log) == 2 and " INFO [notes] player note 1 (ruling, challenge 9): secret-ish" in log[0]
    assert "retracted" in log[1]


def test_rendered_notes_file_lists_active_notes_newest_first(feed):
    a = feed.add("first note")
    feed.add("second note")
    feed.retract(a.id)
    feed.add("third note")
    md = feed.render_path.read_text()
    assert "first note" not in md
    assert md.index("third note") < md.index("second note")
    assert notes.TRUST_LINE in md


def test_attachment_is_copied_and_pointed_at(feed, tmp_path):
    shot = tmp_path / "discord.png"
    shot.write_bytes(b"\x89PNG fake")
    n = feed.add("", files=[shot])
    assert shot.exists()                                        # --file copies, never moves
    stored = feed.root / n.attachments[0]
    assert stored.read_bytes() == b"\x89PNG fake" and stored.parent.name == str(n.id)
    assert str(stored) in notes.render([n], root=feed.root)


# ------------------------------------------------------------------- the drop folder and the file

def test_inbox_drops_become_notes_and_leave_the_inbox(feed):
    feed.init()
    (feed.inbox / "ruling.txt").write_text("No brute force on the login challenge.\n")
    (feed.inbox / "14").mkdir()
    (feed.inbox / "14" / "fix.png").write_bytes(b"PNG")
    (feed.inbox / "14" / "fix.txt").write_text("see the screenshot: new binary")
    (feed.inbox / ".DS_Store").write_bytes(b"x")
    (feed.inbox / ".Screenshot-partial.png").write_bytes(b"x")
    got = feed.sync()
    assert got.problems == []
    by_src = {n.source: n for n in got.notes}
    assert set(by_src) == {"inbox:ruling", "inbox:fix"}
    assert by_src["inbox:ruling"].text == "No brute force on the login challenge."
    assert by_src["inbox:ruling"].challenge is None
    fix = by_src["inbox:fix"]
    assert fix.challenge == "14" and fix.text == "see the screenshot: new binary"
    assert [Path(a).name for a in fix.attachments] == ["fix.png"]
    assert (feed.root / fix.attachments[0]).read_bytes() == b"PNG"
    assert not (feed.inbox / "ruling.txt").exists() and not (feed.inbox / "14").exists()
    assert (feed.inbox / ".DS_Store").exists()                 # hidden files are not notes
    assert feed.sync().notes == []                             # nothing is taken twice


def test_inbox_text_drops_leave_no_credential_in_any_file(feed):
    feed.init()
    (feed.inbox / "r.txt").write_text("rule: use Authorization: Bearer SECRETVALUE123 on the api\n")
    (feed.inbox / "r.png").write_bytes(b"PNG")
    got = feed.sync()
    assert got.problems == [] and len(got.notes) == 1
    note = got.notes[0]
    assert "SECRETVALUE123" not in note.text and "<credential removed>" in note.text
    kept = feed.root / notes.ATTACH_NAME / str(note.id) / "r.txt"     # the drop is kept, scrubbed
    assert kept.read_text() == "rule: use <credential removed> on the api\n"
    assert not (feed.inbox / "r.txt").exists()
    leaked = [p for p in feed.root.rglob("*") if p.is_file() and b"SECRETVALUE123" in p.read_bytes()]
    assert leaked == []


def test_inbox_drops_are_taken_oldest_first(feed):
    feed.init()
    now = time.time()
    early, late = feed.inbox / "zz-first.txt", feed.inbox / "aa-second.txt"
    early.write_text("dropped first")
    late.write_text("dropped second")
    os.utime(early, (now - 200, now - 200))
    os.utime(late, (now - 100, now - 100))
    got = feed.sync().notes
    assert [(n.id, n.text) for n in got] == [(1, "dropped first"), (2, "dropped second")]


def test_a_drop_still_being_written_waits_for_the_next_read(tmp_path):
    f = notes.Feed(tmp_path / "notes", settle=60)
    f.init()
    (f.inbox / "new.txt").write_text("fresh")
    assert f.sync().notes == [] and (f.inbox / "new.txt").exists()
    f.settle = 0
    assert [n.text for n in f.sync().notes] == ["fresh"]


def test_inbox_problems_are_named_not_dropped(feed, tmp_path):
    feed.init()
    deep = feed.inbox / "1" / "2"
    deep.mkdir(parents=True)
    (deep / "x.txt").write_text("too deep")
    (feed.inbox / "empty.txt").write_text("  \n")
    target = tmp_path / "elsewhere.txt"
    target.write_text("linked")
    (feed.inbox / "link.txt").symlink_to(target)
    got = feed.sync()
    assert got.notes == []
    joined = "\n".join(got.problems)
    assert "nested too deep" in joined and "empty" in joined and "symlink" in joined
    assert (deep / "x.txt").exists() and target.exists()


def test_player_notes_file_blocks_become_notes_once(feed):
    feed.init()
    assert feed.sync().notes == []                             # the header comment is not a note
    with open(feed.file_path, "a") as fh:
        fh.write("challenge: 7\nkind: ruling\nNo automated scanning of 7.\n---\nsolve count on 3 is 40\n")
    got = feed.sync().notes
    assert [(n.challenge, n.kind, n.text, n.source) for n in got] == [
        ("7", "ruling", "No automated scanning of 7.", "file"),
        (None, "intel", "solve count on 3 is 40", "file")]
    assert feed.sync().notes == []
    feed.file_path.write_text(feed.file_path.read_text().replace("40", "55"))
    assert [n.text for n in feed.sync().notes] == ["solve count on 3 is 55"]


def test_player_notes_file_bad_block_is_reported_and_retried(feed):
    feed.init()
    with open(feed.file_path, "a") as fh:
        fh.write("kind: rumour\nsomething\n")
    got = feed.sync()
    assert got.notes == [] and "unknown note kind" in got.problems[0]
    feed.file_path.write_text(feed.file_path.read_text().replace("rumour", "intel"))
    assert [n.text for n in feed.sync().notes] == ["something"]


def test_corrupt_file_seen_record_is_a_named_failure(feed, tmp_path, capsys):
    feed.init()
    with open(feed.file_path, "a") as fh:
        fh.write("a block\n")
    seen = feed.root / notes.FILE_SEEN_NAME
    seen.write_text("{not json")
    with pytest.raises(notes.NotesError, match=r"\.file-seen\.json: corrupt"):
        feed.sync()
    assert cli.main(["notes", "--dir", str(feed.root), "list"]) == 2
    assert ".file-seen.json: corrupt" in capsys.readouterr().err
    seen.write_text(json.dumps({"not": "a list"}))
    with pytest.raises(notes.NotesError, match="not a list of block hashes"):
        feed.sync()
    seen.write_text(json.dumps([1, 2]))                          # a list, but not of hashes
    with pytest.raises(notes.NotesError, match="not a list of block hashes"):
        feed.sync()
    seen.unlink()
    assert [n.text for n in feed.sync().notes] == ["a block"]


def test_pending_takes_in_drops_without_a_separate_command(feed):
    feed.init()
    (feed.inbox / "a.md").write_text("dropped")
    assert [i.text for i in feed.pending("x")] == ["dropped"]


# ----------------------------------------------------------------------- the Claude Code hook

def test_hook_response_digest_then_only_new_notes(feed):
    feed.add("old news")
    start = notes.hook_response(feed, {"session_id": "s1", "hook_event_name": "SessionStart"})
    ctx = start["hookSpecificOutput"]
    assert ctx["hookEventName"] == "SessionStart" and "old news" in ctx["additionalContext"]
    assert notes.TRUST_LINE in ctx["additionalContext"]
    assert notes.hook_response(feed, {"session_id": "s1", "hook_event_name": "PostToolUse"}) is None
    feed.add("hot off Discord")
    got = notes.hook_response(feed, {"session_id": "s1", "hook_event_name": "UserPromptSubmit"})
    text = got["hookSpecificOutput"]["additionalContext"]
    assert got["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert "hot off Discord" in text and "old news" not in text


def test_hook_response_scopes_to_the_challenge_and_clips_long_notes(feed):
    feed.add("for 2 only", challenge="2")
    feed.add("A" * 5000)
    got = notes.hook_response(feed, {"session_id": "s", "hook_event_name": "SessionStart"}, challenge="3")
    text = got["hookSpecificOutput"]["additionalContext"]
    assert "for 2 only" not in text
    assert "A" * notes.HOOK_NOTE_CHARS in text and "A" * (notes.HOOK_NOTE_CHARS + 1) not in text
    assert "more characters cut" in text


def test_hook_push_is_capped_in_total_and_keeps_the_trust_line(feed):
    for k in range(8):
        feed.add(f"note{k} " + "B" * notes.HOOK_NOTE_CHARS)
    got = notes.hook_response(feed, {"session_id": "s", "hook_event_name": "SessionStart"})
    text = got["hookSpecificOutput"]["additionalContext"]
    assert len(text) <= notes.HOOK_TOTAL_CHARS
    assert "python -m ctf notes list" in text and "note0 " in text and "note7 " not in text
    assert text.endswith(notes.TRUST_LINE)
    short = notes.render(feed.notes(sync=False)[:1], limit_total=notes.HOOK_TOTAL_CHARS)
    assert "python -m ctf notes list" not in short                # nothing cut, nothing said


def test_total_cap_counts_the_trust_line_for_a_body_just_under_the_cap(feed):
    feed.add("C" * 300)
    items = feed.notes(sync=False)
    tail = len("\n\n" + notes.TRUST_LINE)
    body = len(notes.render(items)) - tail                     # the uncut body
    for limit in (body, body + 1, body + tail // 2, body + tail - 1):    # body fits, body + tail not
        text = notes.render(items, limit_total=limit)
        assert len(text) <= limit, limit
        assert text.endswith(notes.TRUST_LINE) and "python -m ctf notes list" in text
    assert notes.render(items, limit_total=body + tail) == notes.render(items)    # exactly fits


def test_hook_response_refuses_malformed_input(feed):
    with pytest.raises(notes.NotesError, match="unsupported hook event"):
        notes.hook_response(feed, {"session_id": "s", "hook_event_name": "Stop"})
    with pytest.raises(notes.NotesError, match="no session_id"):
        notes.hook_response(feed, {"hook_event_name": "PostToolUse"})
    with pytest.raises(notes.NotesError, match="not a JSON object"):
        notes.hook_response(feed, ["x"])


def test_hook_entry_point_speaks_claude_code_json(feed):
    feed.add("from the player")
    argv = [PY, "-m", "ctf.notes", "--dir", str(feed.root), "hook"]
    r = subprocess.run(argv, input=json.dumps({"session_id": "z", "hook_event_name": "SessionStart"}),
                       capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "from the player" in json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
    r = subprocess.run(argv, input=json.dumps({"session_id": "z", "hook_event_name": "PostToolUse"}),
                       capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 0 and r.stdout == ""
    r = subprocess.run(argv, input="not json", capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 1 and "player-notes hook: JSONDecodeError" in r.stderr


def test_claude_hooks_block_runs_from_any_directory(feed, tmp_path):
    hooks = notes.claude_hooks(feed.root, challenge="4")
    assert set(hooks) == {"SessionStart", "UserPromptSubmit", "PostToolUse"}
    assert hooks["PostToolUse"][0]["matcher"] == "*"
    feed.add("only for 5", challenge="5")
    feed.add("for 4", challenge="4")
    elsewhere = tmp_path / "cwd"
    elsewhere.mkdir()
    cmd = hooks["SessionStart"][0]["hooks"][0]["command"]
    r = run_hook_command(cmd, {"session_id": "q", "hook_event_name": "SessionStart"}, cwd=elsewhere)
    assert r.returncode == 0, r.stderr
    text = json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "for 4" in text and "only for 5" not in text


def test_install_claude_hooks_keeps_mode_and_refuses_existing_hooks(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text(json.dumps({"permissions": {"deny": ["Read(/x)"]}}))
    notes.install_claude_hooks(s, tmp_path / "notes")
    data = json.loads(s.read_text())
    root = str((tmp_path / "notes").resolve())
    assert data["permissions"] == {"deny": ["Read(/x)", f"Edit(/{root}/**)"]}
    assert data["sandbox"]["filesystem"]["denyWrite"] == [root] and "PostToolUse" in data["hooks"]
    assert stat.S_IMODE(s.stat().st_mode) == 0o600
    with pytest.raises(notes.NotesError, match="already has a hooks block"):
        notes.install_claude_hooks(s, tmp_path / "notes")


@pytest.mark.needs_tool("claude")
def test_hook_names_exist_in_the_installed_claude():
    """The hook events and output fields we emit are names the installed Claude Code knows (its
    bundled schema is read as bytes; nothing is run)."""
    import shutil
    data = Path(shutil.which("claude")).resolve().read_bytes()
    names = [*notes.HOOK_EVENTS, "hookSpecificOutput", "hookEventName", "additionalContext", "matcher"]
    assert [n for n in names if n.encode() not in data] == []


# ------------------------------------------------------------------------- tools/claude_launch

def _launch(tmp_path, *args):
    work = tmp_path / "work"
    e = dict(os.environ, CTF_WORKDIR=str(work), CTF_EVENT="csctf")
    e.pop("CTF_CHALLENGE", None)
    r = subprocess.run([PY, str(REPO / "tools" / "claude_launch"), "--workspace", str(tmp_path / "ws"),
                        "--dry-run", *args], capture_output=True, text=True, env=e, timeout=60,
                       stdin=subprocess.DEVNULL)
    settings = tmp_path / "ws" / ".fence" / "claude-settings.json"
    return r, work, settings


def test_claude_launch_pushes_the_event_feed_into_the_session(tmp_path):
    r, work, settings = _launch(tmp_path, "--challenge", "7")
    assert r.returncode == 0, r.stderr
    assert f"player notes: pushed into the session from {(work / 'notes').resolve()}" in r.stderr
    data = json.loads(settings.read_text())
    assert data["sandbox"]["enabled"] is True                   # the fence settings are still there
    root = str((work / "notes").resolve())
    assert root in data["sandbox"]["filesystem"]["denyWrite"]   # the agent cannot forge a note
    assert f"Edit(/{root}/**)" in data["permissions"]["deny"]
    assert data["sandbox"]["filesystem"]["allowWrite"]          # the fence's write roots are kept
    feed = notes.Feed(work / "notes", settle=0)
    feed.add("chal 7: the organizers fixed the binary", challenge="7")
    feed.add("chal 8 only", challenge="8")
    start = data["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    out = run_hook_command(start, {"session_id": "abc", "hook_event_name": "SessionStart"}, cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    text = json.loads(out.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "fixed the binary" in text and "chal 8 only" not in text
    feed.add("new ruling for all", kind="ruling")
    tool = data["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    out = run_hook_command(tool, {"session_id": "abc", "hook_event_name": "PostToolUse"}, cwd=tmp_path)
    text = json.loads(out.stdout)["hookSpecificOutput"]["additionalContext"]
    assert "new ruling for all" in text and "fixed the binary" not in text


def test_claude_launch_no_notes_leaves_the_hooks_out(tmp_path):
    r, _work, settings = _launch(tmp_path, "--no-notes")
    assert r.returncode == 0, r.stderr
    assert "hooks" not in json.loads(settings.read_text()) and "player notes" not in r.stderr


# ----------------------------------------------------------------------------------------- CLI

def test_cli_add_from_text_stdin_and_clipboard(tmp_path, capsys, monkeypatch):
    d = str(tmp_path / "notes")
    assert cli.main(["notes", "--dir", d, "add", "chal", "3", "hint", "--challenge", "3", "--kind", "fix"]) == 0
    assert "note 1 added (fix, challenge 3)" in capsys.readouterr().out
    monkeypatch.setattr(sys, "stdin", io.StringIO("pasted ruling\nsecond line\n"))
    assert cli.main(["notes", "--dir", d, "add", "-"]) == 0
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "pbpaste"
    fake.write_text("#!/bin/sh\nprintf 'from the clipboard'\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    assert cli.main(["notes", "--dir", d, "add", "--paste"]) == 0
    got = notes.Feed(d).notes(sync=False)
    assert [(n.text, n.source) for n in got] == [("chal 3 hint", "cli"),
                                                 ("pasted ruling\nsecond line", "cli"),
                                                 ("from the clipboard", "paste")]
    capsys.readouterr()
    assert cli.main(["notes", "--dir", d, "add", "x", "--paste"]) == 2
    assert "one way" in capsys.readouterr().err


def test_cli_paste_without_pbpaste_is_a_named_failure(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-here"))
    assert cli.main(["notes", "--dir", str(tmp_path / "n"), "add", "--paste"]) == 2
    assert "--paste needs pbpaste" in capsys.readouterr().err


def test_cli_pending_list_show_retract_where(tmp_path, capsys):
    d = str(tmp_path / "notes")
    cli.main(["notes", "--dir", d, "add", "first"])
    cli.main(["notes", "--dir", d, "add", "second", "--challenge", "2"])
    capsys.readouterr()
    assert cli.main(["notes", "--dir", d, "pending", "--agent", "codex-2", "--challenge", "1"]) == 0
    out = capsys.readouterr().out
    assert "1 new player note(s) for codex-2" in out and "first" in out and "second" not in out
    assert cli.main(["notes", "--dir", d, "pending", "--agent", "codex-2", "--challenge", "1"]) == 0
    assert "no new player notes" in capsys.readouterr().out
    assert cli.main(["notes", "--dir", d, "retract", "1", "--reason", "wrong"]) == 0
    capsys.readouterr()
    assert cli.main(["notes", "--dir", d, "list"]) == 0
    out = capsys.readouterr().out
    assert "second" in out and "first" not in out
    assert cli.main(["notes", "--dir", d, "list", "--all"]) == 0
    assert "[RETRACTED: wrong]" in capsys.readouterr().out
    assert cli.main(["notes", "--dir", d, "show", "1"]) == 0
    assert "RETRACTED: wrong" in capsys.readouterr().out
    assert cli.main(["notes", "--dir", d, "show", "9"]) == 2
    assert "no note 9" in capsys.readouterr().err
    assert cli.main(["notes", "--dir", d, "where", "--init"]) == 0
    assert "drop folder:" in capsys.readouterr().out
    assert (Path(d) / "inbox").is_dir() and (Path(d) / "player-notes.md").read_text().startswith("<!--")


def test_cli_sync_reports_problems_with_exit_1(tmp_path, capsys):
    d = tmp_path / "notes"
    f = notes.Feed(d)
    f.init()
    (d / "player-notes.md").write_text("kind: nope\nbody\n")
    assert cli.main(["notes", "--dir", str(d), "sync"]) == 1
    assert "unknown note kind" in capsys.readouterr().err


def test_cli_unwritable_notes_folder_is_a_named_failure(tmp_path, capsys):
    d = tmp_path / "notes"
    notes.Feed(d).add("x")
    os.chmod(d, 0o500)
    try:
        assert cli.main(["notes", "--dir", str(d), "add", "y"]) == 2
    finally:
        os.chmod(d, 0o700)
    assert "cannot use the notes folder: PermissionError" in capsys.readouterr().err


def test_cli_defaults_to_the_event_workdir(capsys):
    assert cli.main(["notes", "where"]) == 0
    assert f"notes folder: {(paths.workdir() / 'notes').resolve()}" in capsys.readouterr().out


def test_cli_claude_hooks_prints_a_settings_block(tmp_path, capsys):
    assert cli.main(["notes", "--dir", str(tmp_path / "n"), "claude-hooks", "--challenge", "5"]) == 0
    block = json.loads(capsys.readouterr().out)["hooks"]
    assert "--challenge 5" in block["PostToolUse"][0]["hooks"][0]["command"]


# ------------------------------------------------------------------------- the event agent rules

@pytest.mark.parametrize("slug", ["csctf", "huntress", "pink", "spooky"])
def test_event_rules_tell_every_agent_how_to_pull_notes(slug):
    for name in ("CLAUDE.md", "AGENTS.md"):
        text = (paths.event_dir(slug) / name).read_text()
        assert "## Player notes" in text
        assert "python -m ctf notes pending --agent <your name> [--challenge <id>]" in text
        assert "tools/claude_launch" in text
