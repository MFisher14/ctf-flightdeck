"""B-112: the toolkits.osint_discord engine, its route, and its run inside the no-model intake.

The snapshot, the challenge and the throwaway checkout are all built here. The intake test runs the
real engine file under the intake network guard with a fake platform adapter object.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import discord_fake
import osint_discord as od
from ctf import discordrecon as dr
from ctf import event, flagfmt, humanops, intake, ledger, paths
from ctf.engines import manifest, router
from ctf.platform.base import Challenge
from ctf.result import SolverResult

P = discord_fake.profile()
REPO = paths.repo_root()
REAL = "RECON{r34l_d1sc0rd_fl4g}"
DECOY = "RECON{example_only}"


@pytest.fixture
def wd(tmp_path, monkeypatch):
    w = tmp_path / "wd"
    w.mkdir()
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    return w


def challenge(wd, cid="77", name="Comms Check", description="The flag is somewhere on the discord.", tags=()):
    d = wd / f"{cid}-comms-check"
    d.mkdir()
    (d / "challenge.json").write_text(json.dumps({"id": int(cid), "name": name, "description": description,
                                                  "tags": list(tags)}))
    return d


def snapshot(wd, *items):
    s = dr.Snapshot()
    s.add(items)
    dr.save(s, dr.snapshot_path(wd))


def cards(wd):
    return humanops.HumanOps(P, wd).cards()


def test_without_a_snapshot_it_is_blocked_and_cards_the_player_once(wd):
    chal = challenge(wd)
    r = od.solve(chal, P)
    assert r.status == "blocked" and r.engine == "toolkits.osint_discord" and r.challenge_id == "77"
    assert "no Discord snapshot" in r.notes and "human step" in r.notes and "discord checklist --challenge 77" in r.notes
    (card,) = cards(wd)
    assert (card.kind, card.challenge_id) == ("discord", "77") and card.id in r.notes and "opened" in r.notes
    again = od.solve(chal, P)
    assert again.status == "blocked" and "is already open" in again.notes and len(cards(wd)) == 1
    assert not (chal / "recon").exists()


def test_the_card_can_be_turned_off(wd):
    r = od.solve(challenge(wd), P, card=False)
    assert r.status == "blocked" and "Task card" not in r.notes and cards(wd) == []


def test_a_brief_that_only_mentions_discord_gets_no_card(wd):
    d = wd / "30-pwn-me"
    d.mkdir()
    (d / "challenge.json").write_text(json.dumps({
        "id": 30, "name": "Pwn Me", "description": "Stuck? Ask on Discord.", "files": ["pwn.zip"],
        "connection_info": "nc pwn.recon-test.example 1337"}))
    r = od.solve(d, P)
    assert r.status == "blocked" and "No task card was opened" in r.notes and cards(wd) == []
    assert "discord checklist --challenge 30 --card" in r.notes
    assert "has files or a target" in r.notes
    # a bare challenge whose brief names Discord only for help: the note says that, not "has files"
    inline = wd / "32-inline"
    inline.mkdir()
    (inline / "challenge.json").write_text(json.dumps({
        "id": 32, "name": "Inline", "description": "Decrypt: 4f2a9c1b77e0d3. Questions? Ask on Discord."}))
    r = od.solve(inline, P)
    assert r.status == "blocked" and cards(wd) == [] and "discord checklist --challenge 32 --card" in r.notes
    assert "does not point into the server" in r.notes and "has files or a target" not in r.notes
    # no challenge.json at all: said so
    nojson = wd / "33-nojson"
    nojson.mkdir()
    r = od.solve(nojson, P)
    assert r.status == "blocked" and cards(wd) == [] and "has no challenge.json" in r.notes
    assert "has files or a target" not in r.notes
    tagged = wd / "31-tagged"
    tagged.mkdir()
    (tagged / "challenge.json").write_text(json.dumps({
        "id": 31, "name": "Tagged", "description": "Find me.", "files": ["x.zip"], "tags": ["discord"]}))
    assert "opened" in od.solve(tagged, P).notes
    assert [c.challenge_id for c in cards(wd)] == ["31"]


def test_candidates_go_to_the_recon_file_and_the_result_carries_no_value(wd):
    chal = challenge(wd)
    snapshot(wd, dr.Item("pin", "#announcements", f"well done: {REAL}"),
             dr.Item("thread-name", f"thread {REAL} leaked", "a thread"),
             dr.Item("message", f"thread {REAL} leaked", f"again {REAL}"),
             dr.Item("channel-topic", "#watch", "Recognition word: halyard"))
    r = od.solve(chal, P)
    assert r.status == "unsure" and r.flags == ()
    report = (chal / "recon" / "discord.md").read_text()
    assert REAL in report and "halyard" in report and "challenge 77 (Comms Check)" in report
    assert "recon/discord.md" in r.notes and "2 Discord candidate(s)" in r.notes
    # intake scans an engine's printed result for flags and would merge them: there must be none,
    # not in the notes and not in an evidence line (a thread's name can hold one)
    printed = r.to_json()
    assert flagfmt.for_profile(P).find_flags(printed) == [] and "halyard" not in printed
    assert r.evidence and all(e.path == "recon/discord.md" for e in r.evidence)
    assert SolverResult.from_json(printed) == r
    assert cards(wd) == []                                   # a snapshot exists: nothing to ask for


def test_flags_are_returned_only_on_request_decoys_last(wd):
    chal = challenge(wd)
    snapshot(wd, dr.Item("rules", "#rules", f"Flag format: {DECOY}"), dr.Item("pin", "#a", REAL),
             dr.Item("channel-topic", "#watch", "Recognition word: halyard"))
    r = od.solve(chal, P, flags=True)
    assert r.status == "candidate" and r.flags == (REAL, DECOY)
    assert "Not attributed to this challenge" in r.notes
    assert od.solve(chal, P, flags="true").flags == (REAL, DECOY)       # as `--opt flags=true` may arrive
    assert od.solve(chal, P, flags=False).flags == ()
    # words only, no event-format value: nothing to return even on request
    snapshot(wd, dr.Item("channel-topic", "#watch", "Recognition word: halyard"))
    only_words = od.solve(chal, P, flags=True)
    assert only_words.status == "unsure" and only_words.flags == ()


def test_a_value_quoted_in_the_brief_is_a_decoy_for_this_challenge(wd):
    chal = challenge(wd, description=f"It is on the discord. Flags look like {REAL}")
    snapshot(wd, dr.Item("pin", "#a", REAL))
    assert od.solve(chal, P).status == "unsure"
    report = (chal / "recon" / "discord.md").read_text()
    assert "| decoy-flag |" in report and "quoted in the challenge brief" in report and "| flag |" not in report
    assert od.solve(chal, P, flags=True).flags == (REAL,)               # still listed, as the decoy it is


def test_no_candidate_is_none_and_a_bad_snapshot_or_option_is_blocked_by_name(wd, tmp_path):
    chal = challenge(wd)
    snapshot(wd, dr.Item("message", "#general", "good morning"))
    r = od.solve(chal, P)
    assert r.status == "none" and "1 snapshot item(s)" in r.notes
    dr.snapshot_path(wd).write_text("{not json")
    bad = od.solve(chal, P)
    assert bad.status == "blocked" and "not JSON" in bad.notes
    other = tmp_path / "other.json"
    other.write_text(json.dumps(dr.Snapshot().to_dict()))
    assert od.solve(chal, P, snapshot=str(other)).status == "none"      # the named snapshot is the one read
    assert od.solve(chal, P, snapshot=str(tmp_path / "absent.json"), card=False).status == "blocked"
    unknown = od.solve(chal, P, flag=True)
    assert unknown.status == "blocked" and "unknown option(s): flag" in unknown.notes


def test_a_snapshot_option_inside_the_discord_app_folder_is_refused_unread(wd, tmp_path):
    chal = challenge(wd)
    inside = tmp_path / "home" / "Library" / "Application Support" / "discord" / "snap.json"
    inside.parent.mkdir(parents=True)
    inside.write_text(json.dumps(dr.Snapshot().to_dict()))          # a valid snapshot: only the place is wrong
    r = od.solve(chal, P, snapshot=str(inside))
    assert r.status == "blocked" and "local Discord app's data folder" in r.notes
    assert cards(wd) == []                                          # refused before any card is opened
    with pytest.raises(dr.DiscordReconError, match="never read"):
        dr.load(inside)                                             # the loader refuses it too
    absent = inside.parent / "Local Storage" / "absent.json"       # not even looked up there
    gone = od.solve(chal, P, snapshot=str(absent))
    assert gone.status == "blocked" and "local Discord app's data folder" in gone.notes
    assert "no Discord snapshot" not in gone.notes and cards(wd) == []


# ------------------------------------------------------------------------------- route and intake

def _manifest():
    (m,) = [m for m in manifest.discover(REPO) if m.id == "toolkits.osint_discord"]
    return m


def test_the_manifest_routes_discord_wording_and_runs_at_intake():
    m = _manifest()
    assert m.intake is not None and m.intake.run == "challenge" and m.intake.select == "route"
    assert m.cost_class == "cheap" and m.needs_tools == () and m.status == "active"
    hit = lambda cat, text: [h.manifest.id for h in router.route(cat, text, manifests=[m])]   # noqa: E731
    assert hit("misc", "The flag is somewhere on the Discord, maybe as a text") == ["toolkits.osint_discord"]
    assert hit("welcome", "Our net runs on DISCORD. Report the recognition word.") == ["toolkits.osint_discord"]
    assert hit("misc", "A harmless service on port 1337") == []


class Adapter:
    kind = "fake"

    def __init__(self, ch):
        self.ch = ch

    def get_challenge(self, cid):
        return self.ch

    def download_files(self, cid, dest):
        return []

    def list_challenges(self):
        return [self.ch]

    def team_solves(self):
        return []

    def submit(self, cid, flag):
        raise AssertionError("intake must never submit")


@pytest.fixture
def checkout(tmp_path):
    """A throwaway checkout holding the real ctf package and only this engine."""
    root = tmp_path / "repo"
    (root / "solvers" / "toolkits").mkdir(parents=True)
    (root / "ctf").symlink_to(REPO / "ctf", target_is_directory=True)
    for name in ("osint_discord.py", "osint_discord.manifest.toml"):
        shutil.copy(REPO / "solvers" / "toolkits" / name, root / "solvers" / "toolkits" / name)
    return root


def _intake(checkout, wd, ch):
    prof = event.load("csctf")
    opts = intake.Options(root=checkout, net_guard="hook")
    return prof, intake.intake_one(ch.id, prof, adapter=Adapter(ch), workdir=wd, options=opts)


def _run_of(rep):
    return [r for r in rep.runs if r.engine == "toolkits.osint_discord"]


def test_intake_runs_it_on_a_challenge_that_is_only_tagged_discord(checkout, tmp_path):
    wd = tmp_path / "wd"
    ch = Challenge(id="15", name="QWERTZ", category="Misc", description="Find me.", tags=("discord",))
    prof, rep = _intake(checkout, wd, ch)
    (run,) = _run_of(rep)                                    # routed by the tag: the description has no such word
    assert run.status == "ok" and run.result_status == "blocked" and run.flags == ()
    (card,) = humanops.HumanOps(prof, wd).cards()
    assert (card.kind, card.challenge_id) == ("discord", "15")
    assert rep.status == "none" and rep.flags == {}
    untagged = Challenge(id="16", name="Plain", category="Misc", description="Find me.")
    assert _run_of(_intake(checkout, wd, untagged)[1]) == []


def test_intake_never_turns_a_discord_flag_into_a_solved_challenge(checkout, tmp_path):
    wd = tmp_path / "wd"
    flag = "CSCTF{only_in_the_discord_snapshot}"
    s = dr.Snapshot()
    s.add([dr.Item("pin", "#announcements", f"gg {flag}")])
    dr.save(s, dr.snapshot_path(wd))
    ch = Challenge(id="9091", name="Comms Check", category="Welcome",
                   description="Our net runs on Discord. Report the recognition word.")
    prof, rep = _intake(checkout, wd, ch)
    (run,) = _run_of(rep)
    assert run.status == "ok" and run.result_status == "unsure" and run.flags == ()
    assert rep.flags == {} and rep.status == "none"          # one lone engine flag would have been `solved`
    report = rep.dir / "recon" / "discord.md"
    assert flag in report.read_text()
    assert humanops.HumanOps(prof, wd).cards() == []
    assert [r["engine"] for r in ledger.read(wd) if r["event"] == "engine.run"] == ["toolkits.osint_discord"]
