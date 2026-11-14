"""B-112: the `ctf discord` command end to end (checklist, ingest, capture, analyze, status).

The profile is synthetic (tests/discord_fake.py) and handed to the command in place of a shipped one;
the API is the loopback fake; the token is a dummy. No request leaves 127.0.0.1.
"""
from __future__ import annotations

import argparse
import io
import json

import pytest

import discord_fake
from discord_fake import GUILD, FakeDiscord, server_routes
from ctf import cli, discordrecon as dr, event, humanops, ledger
from ctf.cli import discord as cli_discord

TOKEN = "not-a-real-token-b112-cli-loopback"
RULES = "Rules\n" + "\n".join(f"- {w}" for w in ["Rope", "Eel", "Cod", "Oar", "Net", "{ brace", "Kelp", "} end"])
FLAG = "RECON{K}"


@pytest.fixture
def run(monkeypatch, tmp_path, capsys):
    """run(profile, *argv) -> (exit code, stdout, stderr), with --workdir tmp_path/wd."""
    wd = tmp_path / "wd"
    wd.mkdir()

    def _run(prof, *argv):
        monkeypatch.setattr(event, "load", lambda slug, root=None: prof)
        p = argparse.ArgumentParser()
        cli_discord.add_arguments(p)
        args = p.parse_args(["--event", prof.slug, "--workdir", str(wd), *argv])
        code = cli_discord.run(args)
        out = capsys.readouterr()
        return code, out.out, out.err

    _run.wd = wd
    return _run


def records(wd, kind):
    return [r for r in ledger.read(wd) if r["event"] == kind]


def everything_written(wd) -> str:
    return "\n".join(p.read_text(errors="replace") for p in sorted(wd.rglob("*")) if p.is_file())


def test_the_command_is_discovered_and_not_broken():
    found = {name: err for name, _mod, err in cli.discover()}
    assert "discord" in found and found["discord"] is None


def test_ingest_then_analyze_finds_the_acrostic_and_records_counts_only(run, tmp_path):
    prof = discord_fake.profile()
    f = tmp_path / "rules.txt"
    f.write_text(RULES)
    code, out, err = run(prof, "ingest", str(f), "--where", "#rules", "--kind", "rules")
    assert code == 0 and "text, 1 item(s), 1 new" in out and err == ""
    snap = dr.load(dr.snapshot_path(run.wd))
    assert [(i.kind, i.where) for i in snap.items] == [("rules", "#rules")]
    code, out, _ = run(prof, "ingest", str(f), "--where", "#rules", "--kind", "rules")
    assert code == 0 and "1 item(s), 0 new" in out                             # the same paste twice: once

    code, out, err = run(prof, "analyze")
    assert code == 0 and f"`{FLAG}`" in out and "acrostic-flag" in out
    report = run.wd / "discord" / "candidates.md"
    assert f"report: {report}" in out and FLAG in report.read_text()
    assert [(r["items"], r["added"], r["source"]) for r in records(run.wd, "discord.ingest")] == \
        [(1, 1, "paste"), (1, 0, "paste")]
    (rec,) = records(run.wd, "discord.analyze")
    assert (rec["items"], rec["candidates"], rec["flags"], rec["event_slug"]) == (1, 1, 1, "recon-test")
    assert "challenge_id" not in rec
    assert FLAG not in (run.wd / "ledger.jsonl").read_text()                  # the ledger keeps no value


def test_analyze_exit_codes_missing_snapshot_and_nothing_found(run, tmp_path):
    prof = discord_fake.profile()
    code, out, err = run(prof, "analyze")
    assert code == 2 and "no Discord snapshot" in err and "human step" in err and out == ""
    f = tmp_path / "chat.txt"
    f.write_text("good morning everyone")
    assert run(prof, "ingest", str(f), "--where", "#general")[0] == 0
    code, out, _ = run(prof, "analyze")
    assert code == 1 and "No candidate" in out
    assert records(run.wd, "discord.analyze")[-1]["candidates"] == 0


def test_analyze_for_a_challenge_uses_its_words_and_writes_its_recon_file(run, tmp_path):
    prof = discord_fake.profile()
    chal = run.wd / "77-comms-check"
    chal.mkdir()
    (chal / "challenge.json").write_text(json.dumps(
        {"id": 77, "name": "Comms Check", "description": "Report the recognition word the watch is broadcasting."}))
    for where, text in (("#lobby", "code word: capstan"), ("#watch", "The watch is broadcasting. Recognition word: halyard")):
        f = tmp_path / "t.txt"
        f.write_text(text)
        assert run(prof, "ingest", str(f), "--where", where, "--kind", "channel-topic")[0] == 0
    code, out, _ = run(prof, "analyze", "--challenge", "77", "--json")
    doc = json.loads(out)
    assert code == 0 and [c["value"] for c in doc["candidates"]] == ["halyard", "capstan"]
    assert doc["report"] == str((chal / "recon" / "discord.md").resolve())
    assert "challenge 77 (Comms Check)" in (chal / "recon" / "discord.md").read_text()
    assert records(run.wd, "discord.analyze")[-1]["challenge_id"] == "77"
    # --cue does by hand what the challenge text does
    code, out, _ = run(prof, "analyze", "--cue", "the watch broadcasting", "--json")
    assert [c["value"] for c in json.loads(out)["candidates"]] == ["halyard", "capstan"]
    code, out, _ = run(prof, "analyze", "--json")
    assert [c["value"] for c in json.loads(out)["candidates"]] == ["capstan", "halyard"]
    code, _, err = run(prof, "analyze", "--challenge", "404")
    assert code == 2 and "no challenge folder for '404'" in err


def test_ingest_reads_a_paste_from_stdin_and_refuses_app_data(run, tmp_path, monkeypatch):
    prof = discord_fake.profile()
    monkeypatch.setattr("sys.stdin", io.StringIO("About me: the code word is `bowline`\n"))
    code, out, _ = run(prof, "ingest", "-", "--where", "member Author", "--kind", "member-about")
    assert code == 0 and "-: text, 1 item(s), 1 new" in out
    assert dr.load(dr.snapshot_path(run.wd)).items[0].kind == "member-about"
    monkeypatch.setattr("sys.stdin", io.StringIO("x"))
    code, _, err = run(prof, "ingest", "-")
    assert code == 2 and "--where" in err
    cache = tmp_path / "home" / "Library" / "Application Support" / "discord" / "Local Storage" / "leveldb" / "1.ldb"
    cache.parent.mkdir(parents=True)
    cache.write_text("RECON{from_the_app_cache}")
    code, _, err = run(prof, "ingest", str(cache), "--where", "#cache")
    assert code == 2 and "never read" in err
    assert "from_the_app_cache" not in everything_written(run.wd)


def test_capture_is_refused_until_the_profile_clears_it(run, monkeypatch):
    monkeypatch.setenv("CTF_DISCORD_TOKEN", TOKEN)
    with FakeDiscord(TOKEN, server_routes()) as fake:
        forbidden = discord_fake.profile(capture="forbidden", api_base=fake.base, allow=["127.0.0.1"], guild_id=GUILD)
        code, out, err = run(forbidden, "capture", "--min-interval", "0")
        assert code == 4 and "refused" in err and "capture = 'forbidden'" in err and out == ""
        unscoped = discord_fake.profile(capture="bot", api_base=fake.base, allow=[], guild_id=GUILD)
        code, _, err = run(unscoped, "capture", "--min-interval", "0")
        assert code == 4 and "rules.public_fetch_allow" in err
        assert fake.requests == []
    assert not dr.snapshot_path(run.wd).exists() and records(run.wd, "discord.capture") == []


def test_capture_needs_the_token_variable_and_a_server_id(run, monkeypatch):
    monkeypatch.delenv("CTF_DISCORD_TOKEN", raising=False)
    with FakeDiscord(TOKEN, server_routes()) as fake:
        prof = discord_fake.profile(capture="bot", api_base=fake.base, allow=["127.0.0.1"])
        code, _, err = run(prof, "capture", "--guild", GUILD, "--min-interval", "0")
        assert code == 4 and "$CTF_DISCORD_TOKEN is not set" in err
        monkeypatch.setenv("CTF_DISCORD_TOKEN", TOKEN)
        code, _, err = run(prof, "capture", "--min-interval", "0")
        assert code == 2 and "no server id" in err and "guild_id" in err
        assert fake.requests == []


def test_capture_end_to_end_and_the_token_is_written_nowhere(run, monkeypatch):
    monkeypatch.setenv("CTF_DISCORD_TOKEN", TOKEN)
    with FakeDiscord(TOKEN, server_routes()) as fake:
        prof = discord_fake.profile(capture="bot", api_base=fake.base, allow=["127.0.0.1"], guild_id=GUILD)
        code, out, err = run(prof, "capture", "--min-interval", "0")
        n = len(fake.requests)
    assert code == 0 and err == ""
    assert f"in {n} request(s)" in out and "PARTIAL" not in out
    assert "note: #locked: pins: not readable by the bot (HTTP 403)" in out
    snap = dr.load(dr.snapshot_path(run.wd))
    assert snap.guild == {"id": GUILD, "name": "Recon Test Fleet"}
    assert any(i.kind == "channel-topic" and "halyard" in i.text for i in snap.items)
    assert any("#locked" in note for note in snap.notes())
    (rec,) = records(run.wd, "discord.capture")
    assert (rec["requests"], rec["partial"], rec["guild_id"], rec["items"] == rec["added"] > 20) == (n, False, GUILD, True)
    assert TOKEN not in out + err and TOKEN not in everything_written(run.wd)

    code, out, _ = run(prof, "analyze")
    assert code == 0 and out.index("RECON{A4}") < out.index("RECON{example_flag_here}")
    code, out, _ = run(prof, "status")
    assert code == 0 and "from Recon Test Fleet" in out and "capture via api" in out and "channel-topic" in out
    code, out, _ = run(prof, "checklist")
    assert "[x] Every channel's details" in out and "python -m ctf discord capture" in out
    assert "[ ] The challenge author's" in out                                  # a bot cannot read profiles


def test_a_partial_capture_says_so(run, monkeypatch):
    monkeypatch.setenv("CTF_DISCORD_TOKEN", TOKEN)
    with FakeDiscord(TOKEN, server_routes()) as fake:
        prof = discord_fake.profile(capture="bot", api_base=fake.base, allow=["127.0.0.1"], guild_id=GUILD)
        code, out, _ = run(prof, "capture", "--min-interval", "0", "--max-requests", "6")
    assert code == 0 and "PARTIAL" in out and "request budget (6) is spent" in out
    assert records(run.wd, "discord.capture")[0]["partial"] is True


def test_checklist_and_its_task_card(run):
    prof = discord_fake.profile()
    code, out, _ = run(prof, "checklist", "--challenge", "77")
    assert code == 0 and "challenge 77" in out and "[ ] Join the server" in out and "task card" not in out
    assert humanops.HumanOps(prof, run.wd).cards() == []
    code, out, _ = run(prof, "checklist", "--challenge", "77", "--card")
    assert code == 0 and "opened" in out
    code, out, _ = run(prof, "checklist", "--challenge", "77", "--card", "--json")
    doc = json.loads(out)
    assert doc["card_created"] is False and doc["capture"] == "forbidden" and doc["snapshot"] is None
    assert [p["key"] for p in doc["places"]][:2] == ["join", "hidden"]
    cards = humanops.HumanOps(prof, run.wd).cards()
    assert [(c.kind, c.challenge_id) for c in cards] == [("discord", "77")] and cards[0].id == doc["card"]
    code, _, err = run(prof, "checklist", "--card")
    assert code == 2 and "--card needs --challenge" in err


def test_status_without_a_snapshot_is_a_named_error(run):
    code, _, err = run(discord_fake.profile(), "status")
    assert code == 2 and "no Discord snapshot" in err
