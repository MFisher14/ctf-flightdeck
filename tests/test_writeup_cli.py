"""`flightdeck writeups RUN_DIR`: drafts written into the run folder, from real run folders.

The command's own Typer app is invoked (the main CLI mounts it with add_typer). Polish runs
against FakeModelServer through a config file in tmp_path; nothing here reaches a real API.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import writeup, writeup_cli
from ctf_flightdeck.runrecord import load_run
from fake_model import FakeModelServer, FakeReply, text_reply
from test_writeup import ALPHA, alpha_run, frozen_of, l1_run, surrogate_run

runner = CliRunner()


def invoke(*args: str | Path):
    return runner.invoke(writeup_cli.app, [str(a) for a in args])


def config_file(tmp_path: Path, server: FakeModelServer, key_env: str = "") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(f'[api]\nbase_url = "{server.base_url}"\nkey_env = "{key_env}"\n\n[models]\nladder = ["fake/model"]\n')
    return path


def test_every_solved_challenge_gets_its_draft_and_nothing_else_does(tmp_path):
    record = alpha_run(tmp_path)
    result = invoke(record.dir)
    assert result.exit_code == 0, result.output
    folder = record.dir / "writeups"
    assert sorted(p.name for p in folder.iterdir()) == ["a.md"]  # Beta was not solved
    assert (folder / "a.md").read_text(encoding="utf-8") == writeup.draft(record, "a")
    assert result.stdout == f"wrote {folder / 'a.md'}\n"
    assert result.stderr == ""


def test_redact_keeps_the_flag_out_of_every_file(tmp_path):
    record = alpha_run(tmp_path)
    assert invoke(record.dir, "--redact").exit_code == 0
    text = (record.dir / "writeups" / "a.md").read_text(encoding="utf-8")
    assert ALPHA not in text and text == writeup.draft(record, "a", redact=True)


def test_writeups_take_the_event_log_the_run_printed_too(tmp_path):
    record = alpha_run(tmp_path)
    result = invoke(record.dir / "events.jsonl")
    assert result.exit_code == 0, result.output
    assert (record.dir / "writeups" / "a.md").read_text(encoding="utf-8") == writeup.draft(record, "a")
    other = invoke(record.dir / "lanes" / "L01.jsonl")
    assert other.exit_code == 2 and "give the run folder (the one holding events.jsonl) or its events.jsonl" in other.stderr


def test_the_board_fills_in_what_the_run_log_lacks(tmp_path):
    record = l1_run(tmp_path)
    for lane in (record.dir / "lanes").iterdir():
        lane.unlink()
    path = record.dir / "events.jsonl"  # an older log: its releases do not name the challenges
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    for line in lines:
        if line["kind"] == "release":
            line["data"].pop("board")
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    board = tmp_path / "board"
    (board / "d").mkdir(parents=True)
    (board / "d" / "challenge.json").write_text(json.dumps({"name": "Delta", "category": "crypto", "points": 100}))
    result = invoke(record.dir, "--board", board)
    assert result.exit_code == 0, result.output
    text = (record.dir / "writeups" / "d.md").read_text(encoding="utf-8")
    assert text.startswith("# Delta\n") and "- Category: cry" in text and "- Points: 100" in text


def test_a_draft_that_exists_is_kept_unless_forced(tmp_path):
    record = alpha_run(tmp_path)
    target = record.dir / "writeups" / "a.md"
    target.parent.mkdir()
    target.write_text("my edits\n")
    result = invoke(record.dir)
    assert result.exit_code == 1
    assert target.read_text() == "my edits\n"
    assert f"flightdeck: {target} exists; kept it (pass --force to replace it)" in result.stderr
    assert invoke(record.dir, "--force").exit_code == 0
    assert target.read_text(encoding="utf-8") == writeup.draft(record, "a")


def test_a_symlink_where_a_draft_goes_is_replaced_never_written_through(tmp_path):
    record = alpha_run(tmp_path)
    outside = tmp_path / "precious.txt"
    outside.write_text("keep me\n")
    folder = record.dir / "writeups"
    folder.mkdir()
    (folder / "a.md").symlink_to(outside)
    assert invoke(record.dir).exit_code == 1  # exists (as a link): kept without --force
    assert invoke(record.dir, "--force").exit_code == 0
    assert outside.read_text() == "keep me\n"
    assert not (folder / "a.md").is_symlink() and (folder / "a.md").read_text(encoding="utf-8").startswith("# Alpha")
    assert sorted(p.name for p in folder.iterdir()) == ["a.md"]  # no temporary file left behind


def test_a_writeups_folder_that_is_a_symlink_is_refused(tmp_path):
    record = alpha_run(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (record.dir / "writeups").symlink_to(elsewhere, target_is_directory=True)
    result = invoke(record.dir)
    assert result.exit_code == 2
    assert "writeups is a symlink; flightdeck does not write drafts through symlinks" in result.stderr
    assert list(elsewhere.iterdir()) == []


def test_a_challenge_id_that_cannot_name_a_file_is_reported_and_writes_nothing(tmp_path):
    record = alpha_run(tmp_path)
    events = record.dir / "events.jsonl"
    lines = events.read_text().splitlines()
    forged = {"at": 999.0, "wall": "", "kind": "submit", "text": "", "lane": None, "challenge": "../../evil",
              "alert": None, "data": {"flag": "t{evil}", "correct": True, "by": "platform"}}
    events.write_text("\n".join(lines[:-1] + [json.dumps(forged), lines[-1]]) + "\n")
    result = invoke(record.dir)
    assert result.exit_code == 1
    assert "flightdeck: '../../evil': this challenge id cannot name a file, so no draft was written" in result.stderr
    assert sorted(p.name for p in (record.dir / "writeups").iterdir()) == ["a.md"]
    assert not (tmp_path / "evil.md").exists() and not (record.dir.parent / "evil.md").exists()


def test_a_lone_surrogate_in_the_run_neither_stops_the_command_nor_loses_a_draft(tmp_path):
    record = surrogate_run(tmp_path)  # a plan from the model holds one; Beta was solved after Alpha
    result = invoke(record.dir)
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 0, result.output
    folder = record.dir / "writeups"
    assert sorted(p.name for p in folder.iterdir()) == ["a.md", "b.md"]  # no temporary file left, none lost
    assert "`decode the emoji \\ud83d note`" in (folder / "a.md").read_text(encoding="utf-8")  # escaped


def test_a_draft_utf8_cannot_hold_is_refused_and_leaves_no_temporary_file(tmp_path):
    with pytest.raises(writeup_cli._Refused, match=r"cannot write .*a\.md: the draft holds text that is not valid Unicode"):
        writeup_cli._write(tmp_path / "a.md", "a lone surrogate: \ud83d\n")
    assert list(tmp_path.iterdir()) == []


def test_a_folder_that_is_not_a_run_is_an_error(tmp_path):
    result = invoke(tmp_path)
    assert result.exit_code == 2
    assert "no events.jsonl (is this a flightdeck run folder?)" in result.stderr


def test_a_run_with_no_solve_says_so_and_writes_nothing(tmp_path):
    record = alpha_run(tmp_path)
    events = record.dir / "events.jsonl"
    events.write_text("".join(line + "\n" for line in events.read_text().splitlines() if '"kind": "submit"' not in line))
    result = invoke(record.dir)
    assert result.exit_code == 0
    assert result.stdout == "no challenge was solved in this run: no writeups to draft\n"
    assert result.stderr == ("flightdeck: L01's transcript says it solved a, but events.jsonl has no accepted flag "
                             "for it, so it gets no draft\n")
    assert not (record.dir / "writeups").exists()


def test_lines_the_run_log_lost_are_named_on_the_terminal_too(tmp_path):
    record = alpha_run(tmp_path)
    with (record.dir / "events.jsonl").open("a") as handle:
        handle.write("{not json\n")
    result = invoke(record.dir)
    assert result.exit_code == 0
    assert "events.jsonl:" in result.stderr and "not JSON" in result.stderr


# ---------------------------------------------------------------------- --polish


def test_polish_writes_the_tidied_draft_and_what_it_cost(tmp_path):
    record = alpha_run(tmp_path)
    reply = lambda r: text_reply(frozen_of(r).replace("## Approach", "## How it went"), cost=0.0015)  # noqa: E731
    with FakeModelServer(responder=reply) as server:
        result = invoke(record.dir, "--polish", "fake/model", "--config", config_file(tmp_path, server))
    assert result.exit_code == 0, result.output
    text = (record.dir / "writeups" / "a.md").read_text(encoding="utf-8")
    assert text == writeup.draft(record, "a").replace("## Approach", "## How it went")
    assert result.stdout.splitlines()[-1] == "polish: 1 of 1 drafts with fake/model, 120 tokens, $0.00"
    (request,) = server.requests
    assert request["json"]["model"] == "fake/model" and ALPHA not in json.dumps(request["json"])


def test_a_refused_polish_keeps_the_plain_draft_and_says_why(tmp_path):
    record = alpha_run(tmp_path)
    with FakeModelServer(responder=lambda r: text_reply(frozen_of(r) + "\nSee [this](http://example.com).")) as server:
        result = invoke(record.dir, "--polish", "fake/model", "--config", config_file(tmp_path, server))
    assert result.exit_code == 1
    target = record.dir / "writeups" / "a.md"
    assert target.read_text(encoding="utf-8") == writeup.draft(record, "a")
    assert f"wrote {target} (not polished)" in result.stdout
    assert f"flightdeck: {target}: not polished: the reply adds a link or an image (a square bracket)" in result.stderr
    assert "polish: 0 of 1 drafts with fake/model, 120 tokens, cost unknown" in result.stdout  # refused, still spent


def test_a_failed_model_call_keeps_the_plain_draft_and_says_why(tmp_path):
    record = alpha_run(tmp_path)
    with FakeModelServer([FakeReply(401, {"error": {"message": "bad key"}})]) as server:
        result = invoke(record.dir, "--polish", "fake/model", "--config", config_file(tmp_path, server))
    assert result.exit_code == 1
    assert (record.dir / "writeups" / "a.md").read_text(encoding="utf-8") == writeup.draft(record, "a")
    assert "not polished: the model API answered HTTP 401 (Unauthorized): bad key" in result.stderr
    assert "polish: 0 of 1 drafts with fake/model, 0 tokens, $0.00" in result.stdout


def test_a_model_name_that_is_not_text_is_shown_with_a_mark(tmp_path):
    record = alpha_run(tmp_path)
    model = "fake\udcffmodel"  # a byte that is not UTF-8 on the command line reaches Python as a lone surrogate
    with FakeModelServer(responder=lambda r: text_reply(frozen_of(r))) as server:
        result = invoke(record.dir, "--polish", model, "--config", config_file(tmp_path, server))
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines()[-1].startswith("polish: 1 of 1 drafts with fake\\xffmodel, ")  # the byte, escaped


def test_polish_without_a_usable_config_stops_before_writing_anything(tmp_path):
    record = alpha_run(tmp_path)
    result = invoke(record.dir, "--polish", "fake/model", "--config", tmp_path / "missing.toml")
    assert result.exit_code == 2
    assert "--polish needs the model API from your config:" in result.stderr and "no config file" in result.stderr
    assert not (record.dir / "writeups").exists()


def test_polish_names_a_missing_key_variable_and_never_shows_a_value(tmp_path, monkeypatch):
    record = alpha_run(tmp_path)
    monkeypatch.delenv("FLIGHTDECK_TEST_POLISH_KEY", raising=False)
    with FakeModelServer() as server:
        result = invoke(record.dir, "--polish", "fake/model", "--config", config_file(tmp_path, server, "FLIGHTDECK_TEST_POLISH_KEY"))
    assert result.exit_code == 2
    assert "the variable FLIGHTDECK_TEST_POLISH_KEY, which is not set: put FLIGHTDECK_TEST_POLISH_KEY=<your key> in" in result.stderr
    assert server.requests == [] and not (record.dir / "writeups").exists()


def test_polish_sends_the_key_only_in_the_authorization_header(tmp_path, monkeypatch):
    record = alpha_run(tmp_path)
    key = "fake-polish-key-for-tests"
    monkeypatch.setenv("FLIGHTDECK_TEST_POLISH_KEY", key)
    with FakeModelServer(responder=lambda r: text_reply(frozen_of(r))) as server:
        result = invoke(record.dir, "--polish", "fake/model", "--config", config_file(tmp_path, server, "FLIGHTDECK_TEST_POLISH_KEY"))
    assert result.exit_code == 0, result.output
    (request,) = server.requests
    assert request["headers"]["authorization"] == f"Bearer {key}"
    assert key not in json.dumps(request["json"]) and key not in result.output
    assert key not in (record.dir / "writeups" / "a.md").read_text(encoding="utf-8")


def test_polish_on_an_anthropic_config_goes_through_the_messages_api(tmp_path, monkeypatch):
    from fake_anthropic import FakeAnthropicServer, text_message

    record = alpha_run(tmp_path)
    key = "fake-claude-polish-key-for-tests"
    monkeypatch.setenv("FLIGHTDECK_TEST_CLAUDE_KEY", key)

    def polished(request: dict) -> dict:
        frozen = request["json"]["messages"][0]["content"][0]["text"]  # the draft is the user turn
        return text_message(frozen.replace("## Approach", "## How it went"), model="claude-haiku-5-5")

    with FakeAnthropicServer(responder=polished) as server:
        path = tmp_path / "config.toml"
        path.write_text(f'[api]\nprovider = "anthropic"\nbase_url = "{server.base_url}"\nkey_env = "FLIGHTDECK_TEST_CLAUDE_KEY"\n'
                        '[models]\nladder = ["claude-haiku-5-5"]\n')
        result = invoke(record.dir, "--polish", "claude-haiku-5-5", "--config", path)
    assert result.exit_code == 0, result.output
    assert (record.dir / "writeups" / "a.md").read_text(encoding="utf-8") == writeup.draft(record, "a").replace(
        "## Approach", "## How it went")
    (request,) = server.requests
    assert request["path"] == "/v1/messages" and request["headers"]["authorization"] == f"Bearer {key}"
    assert request["json"]["system"][0]["text"] == writeup.POLISH_INSTRUCTIONS
    assert key not in result.output


def test_the_main_cli_can_mount_it_at_the_top_level():
    import typer

    main = typer.Typer(rich_markup_mode="markdown")  # as flightdeck's own app renders help

    @main.command()
    def other() -> None:  # a second command, so the main app is a group like flightdeck's
        pass

    main.add_typer(writeup_cli.app)
    result = runner.invoke(main, ["writeups", "--help"])
    assert result.exit_code == 0 and "--redact" in result.stdout and "--polish" in result.stdout
    flat = " ".join(re.sub(r"[\u2502\u256d\u256e\u2570\u256f\u2500]", " ", result.stdout).split())  # no box lines
    assert "Write <flag> in place of the flag wherever" in flat  # not eaten as HTML by the Markdown help
