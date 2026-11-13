"""B-131: the engine web.client_replay, `ctf client-replay`, and the fast-lane and web_evidence hooks.

The handout is built in the test: a raw "disk image" of zeros holding a shipped browser's source
text. The replay talks only to ctf.livereplay's web service on 127.0.0.1.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import client_replay as engine
import web_evidence
from ctf import config as _config
from ctf import event, fastlane, ledger, livereplay, paths
from ctf.cli import client_replay as cli_mod
from ctf.engines import manifest, router
from ctf.result import SolverResult

UA = "PINK-OS-CTF/1.0"
HEAD = "PINK{W0w,_P1nk+_0S_1s"
TAIL = "_b3tt3r_th4n_W1ND0WS_4nd_L1NUX}"
FLAG = HEAD + TAIL


def profile(scope_entries=("127.0.0.0/8",), **rules):
    return event.parse({
        "slug": "replay-test", "name": "replay test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.x-platform.test"},
        "flag": {"prefixes": ["PINK"]},
        "rules": {"submit_mode": "auto", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_entries), **rules},
    }, src="tests/test_web_client_replay.py")


def handout(tmp_path, home: str, ua: str = UA, name: str = "19-pink-os") -> Path:
    """A challenge folder whose data image holds the shipped browser's source, as it lies on disk."""
    d = tmp_path / name
    (d / "files").mkdir(parents=True)
    src = (f"#!/usr/bin/env python3\nHOME = '{home}'\n"
           f"def fetch(url):\n    return urlopen(Request(url, headers={{'User-Agent': '{ua}'}}))\n").encode()
    img = bytearray(64 * 1024)
    img[20000:20000 + len(src)] = src
    (d / "files" / "data.img").write_bytes(bytes(img))
    (d / "files" / "notes.txt").write_bytes(b"docs at https://docs.example.org/manual\n")
    return d


def routes(tail_body=TAIL + "\n"):
    return {
        "/": {"body": '<html><a href="/ctf">PINK+ CTF</a></html>', "headers": {"Content-Type": "text/html"}},
        "/ctf": {"body": "<html>please log in</html>", "headers": {"Content-Type": "text/html"},
                 "variants": [{"when": {"User-Agent": UA}, "body": tail_body,
                               "headers": {"Content-Type": "text/plain"}}]},
    }


def kinds(res):
    return [e.kind for e in res.evidence]


class Recorder:
    def __init__(self):
        self.opened = []

    def __call__(self, scheme, host, port, timeout):
        self.opened.append((scheme, host, port))
        raise ConnectionRefusedError("recorder: no connection in this test")


# ------------------------------------------------------------------------------------------- engine

def test_offline_run_names_the_client_and_what_a_replay_would_contact(tmp_path):
    d = handout(tmp_path, "http://127.0.0.1:8099/")
    rec = Recorder()
    res = engine.solve(d, profile(), connect=rec)
    assert rec.opened == []                                   # the default run is offline
    assert res.status == "unsure" and res.flags == () and res.engine == "web.client_replay"
    ua, url = res.evidence
    where = (d / "files" / "data.img").read_bytes().index(b"User-Agent")
    assert where > 20000 and (ua.kind, ua.path, ua.offset) == ("user-agent", "files/data.img", where)
    assert UA in ua.detail and url.kind == "client-url" and "http://127.0.0.1:8099/" in url.detail
    assert "python -m ctf client-replay run" in res.notes
    saved = json.loads((d / "recon/client/constants.json").read_text())
    assert [c["value"] for c in saved["user_agents"]] == [UA]
    assert {c["value"]: c["near_ua"] for c in saved["urls"]} == {"http://127.0.0.1:8099/": True,
                                                                 "https://docs.example.org/manual": False}
    assert not (d / "recon/client/replay.json").exists()


def test_offline_run_says_which_client_urls_the_scope_refuses(tmp_path):
    d = handout(tmp_path, "https://pink.example.org/")
    res = engine.solve(d, profile())
    assert res.status == "unsure" and kinds(res) == ["user-agent", "client-url-refused"]
    assert "https://pink.example.org/" in res.evidence[1].detail and "live_service_scope" in res.evidence[1].detail
    assert "the player decides" in res.notes


def test_no_custom_user_agent_is_none(tmp_path):
    d = handout(tmp_path, "http://127.0.0.1:8099/", ua="curl/8.5.0")
    res = engine.solve(d, profile(), replay=True, connect=Recorder())
    assert res.status == "none" and "no custom User-Agent" in res.notes and "1 stock" in res.notes
    with_stock = engine.solve(d, profile(), include_stock=True)
    assert with_stock.status == "unsure"                      # asked for, a stock one is replayable too


def test_replay_finds_the_tail_one_hop_from_the_home_page_and_does_not_complete_it(tmp_path):
    with livereplay.WebReplay(routes()) as svc:
        d = handout(tmp_path, svc.base_url + "/")
        res = engine.solve(d, profile(), replay=True, interval=0)
        base = svc.base_url
    assert res.status == "unsure" and res.flags == ()
    frag = next(e for e in res.evidence if e.kind == "fragment-tail")
    assert repr(TAIL) in frag.detail and f"{base}/ctf" in frag.detail and UA in frag.detail
    diff = next(e for e in res.evidence if e.kind == "ua-diff")
    assert f"{base}/ctf (hop 1)" in diff.detail and "content type text/plain instead of text/html" in diff.detail
    assert "fragment only" in res.notes and "not completed" in res.notes
    rep = json.loads((d / "recon/client/replay.json").read_text())
    assert rep["requests"] == 4 and [f["value"] for f in rep["fragments"]] == [TAIL]
    assert all("body" not in r for r in rep["responses"])


def test_a_literal_head_joins_a_literal_tail_into_a_candidate(tmp_path):
    with livereplay.WebReplay(routes()) as svc:
        d = handout(tmp_path, svc.base_url + "/")
        res = engine.solve(d, profile(), replay=True, interval=0, head=HEAD)
        loose = engine.solve(d, profile(), replay=True, interval=0, head="pink{W0w,_P1nk+_0S_1s")
    assert res.status == "candidate" and res.flags == (FLAG,)
    join = next(e for e in res.evidence if e.kind == "join")
    assert repr(HEAD) in join.detail and repr(TAIL) in join.detail and "nothing added or changed" in join.detail
    # a head that would need an edit to fit (here its case) is not joined: that would be a guess
    assert loose.status == "unsure" and loose.flags == () and "not joined" in loose.notes


def test_a_flag_served_only_to_the_shipped_user_agent_is_solved(tmp_path):
    with livereplay.WebReplay(routes(tail_body=f"well done: {FLAG}\n")) as svc:
        d = handout(tmp_path, svc.base_url + "/")
        res = engine.solve(d, profile(), replay=True, interval=0)
    assert res.status == "solved" and res.flags == (FLAG,)
    wire = next(e for e in res.evidence if e.kind == "wire")
    assert "only with User-Agent" in wire.detail and UA in wire.detail


def test_a_flag_every_request_receives_is_only_a_candidate(tmp_path):
    r = {"/": {"body": f"hello {FLAG}", "variants": [{"when": {"User-Agent": UA}, "body": f"hi client {FLAG}"}]}}
    with livereplay.WebReplay(r) as svc:
        d = handout(tmp_path, svc.base_url + "/")
        res = engine.solve(d, profile(), replay=True, interval=0)
    assert res.status == "candidate" and res.flags == (FLAG,)
    assert any("the normal request received it too" in e.detail for e in res.evidence if e.kind == "wire")


def test_a_flag_on_a_page_that_changes_by_itself_is_only_a_candidate(tmp_path, monkeypatch):
    """Every reply carries a different whole flag (a nonce-bearing decoy): the shipped User-Agent's
    value is new only because the page never repeats, so the engine must not call it solved."""
    from ctf import clientreplay as cr
    sent = []

    def fake_get(url, ua, *, profile=None, timeout=None, max_bytes=None, connect=None):
        sent.append((url, ua))
        return 200, {"content-type": "text/plain"}, f"token PINK{{n0nce_{len(sent)}}}".encode(), False

    monkeypatch.setattr(cr, "get", fake_get)
    d = handout(tmp_path, "http://127.0.0.1:8099/")
    res = engine.solve(d, profile(), replay=True, interval=0, hops=0)
    assert [ua for _u, ua in sent] == [cr.DEFAULT_BASELINE_UA, UA, cr.DEFAULT_BASELINE_UA]
    assert res.status == "candidate" and res.status != "solved"
    assert set(res.flags) == {"PINK{n0nce_1}", "PINK{n0nce_2}"}
    assert any("on a page that changes by itself" in e.detail for e in res.evidence if e.kind == "wire")
    assert not any("only with User-Agent" in e.detail for e in res.evidence)


def test_the_same_reply_for_every_user_agent_is_none(tmp_path):
    with livereplay.WebReplay({"/": {"body": "same for all"}}) as svc:
        d = handout(tmp_path, svc.base_url + "/")
        res = engine.solve(d, profile(), replay=True, interval=0)
    assert res.status == "none" and "same replies as a normal request" in res.notes


def test_replay_contacts_nothing_the_scope_refuses(tmp_path):
    d = handout(tmp_path, "https://board.x-platform.test/")       # the client's home is the event platform
    rec = Recorder()
    res = engine.solve(d, profile(), replay=True, interval=0, connect=rec)
    assert rec.opened == [] and res.status == "unsure" and res.flags == ()
    assert "event platform" in res.evidence[1].detail and "replay not run" in res.notes
    assert not (d / "recon/client/replay.json").exists()
    empty = engine.solve(d, profile(scope_entries=()), replay=True, interval=0, connect=rec)
    assert rec.opened == [] and empty.status == "unsure" and "empty rules.live_service_scope" in empty.evidence[1].detail


def test_a_passed_url_and_user_agent_are_replayed_too(tmp_path):
    with livereplay.WebReplay(routes()) as svc:
        d = handout(tmp_path, "https://pink.example.org/", ua="curl/8.5.0")
        res = engine.solve(d, profile(), replay=True, interval=0, url=svc.base_url + "/", user_agent=[UA])
        sent = sorted({(p, h["user-agent"]) for _m, p, h in svc.requests if h["user-agent"] == UA})
    assert sent == [("/", UA), ("/ctf", UA)] and any(e.kind == "fragment-tail" for e in res.evidence)


def test_the_gates_count_is_shown_beside_a_fragment(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    prof = profile(wrong_answer_stop=3)
    for _ in range(3):
        ledger.append("platform.submit", workdir=tmp_path / "work", event_slug="replay-test", challenge_id="19",
                      status="incorrect", judged=True, guess=False)
    with livereplay.WebReplay(routes()) as svc:
        d = handout(tmp_path, svc.base_url + "/")
        res = engine.solve(d, prof, replay=True, interval=0, challenge_id="19")
    assert res.challenge_id == "19"
    assert "STOP: challenge 19: 3 wrong answer(s) of 3" in res.notes and "only the player can approve" in res.notes


@pytest.mark.parametrize("opts, needle", [
    ({"replay": "maybe"}, "expected true or false"),
    ({"url": 5}, "url takes a string"),
    ({"max_bytes": 0}, "max_bytes"),
])
def test_bad_options_block_with_a_reason(tmp_path, opts, needle):
    res = engine.solve(handout(tmp_path, "http://127.0.0.1:8099/"), profile(), **opts)
    assert res.status == "blocked" and needle in res.notes


def test_a_bad_replay_option_blocks_after_the_harvest(tmp_path):
    res = engine.solve(handout(tmp_path, "http://127.0.0.1:8099/"), profile(), replay=True, hops=-2,
                       connect=Recorder())
    assert res.status == "blocked" and "hops must be" in res.notes and kinds(res)[0] == "user-agent"


# ----------------------------------------------------------------------------- manifest and routing

def test_the_engine_is_routed_and_has_an_offline_intake_adapter(tmp_path):
    m = next(x for x in manifest.discover() if x.id == "web.client_replay")
    assert m.entry_raw == "solvers.web.client_replay:solve" and m.intake is not None
    assert (m.intake.run, m.intake.select) == ("challenge", "files") and "ext:.img" in m.intake.match
    d = handout(tmp_path, "http://127.0.0.1:8099/")
    (d / "files" / "uefi_disk.img").write_bytes(bytes(2048))
    by_file = [h.manifest.id for h in router.route("stego", "an operating system to look at", d / "files")]
    assert "web.client_replay" in by_file
    by_word = [h.manifest.id for h in router.route("web", "the server checks the User-Agent of our browser")]
    assert "web.client_replay" in by_word
    assert "web.client_replay" not in [h.manifest.id for h in router.route("crypto", "an RSA key with small e")]


# ---------------------------------------------------------------------------------------------- CLI

def cli(*argv) -> int:
    p = argparse.ArgumentParser()
    cli_mod.add_arguments(p)
    return cli_mod.run(p.parse_args(list(argv)))


def test_cli_harvest_lists_the_client(tmp_path, capsys):
    d = handout(tmp_path, "https://pink.example.org/")
    assert cli("harvest", str(d)) == 0
    out = capsys.readouterr().out
    assert f"custom  {UA!r}  files/data.img@" in out and "client  https://pink.example.org/" in out
    assert "docs.example.org" not in out                      # not beside the client: listed only with --all
    assert cli("harvest", str(d), "--all") == 0
    assert "other   https://docs.example.org/manual" in capsys.readouterr().out
    assert cli("harvest", str(d), "--json") == 0
    assert [c["value"] for c in json.loads(capsys.readouterr().out)["user_agents"]] == [UA]


def test_cli_harvest_exit_codes(tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.txt").write_text("nothing here")
    assert cli("harvest", str(plain)) == 1 and "no custom User-Agent" in capsys.readouterr().out
    assert cli("harvest", str(tmp_path / "missing")) == 2
    assert "not a file or folder" in capsys.readouterr().err
    d = handout(tmp_path, "https://pink.example.org/")
    assert cli("harvest", str(d), "--max-bytes", "100") == 1
    assert "INCOMPLETE files/data.img: the byte budget ran out" in capsys.readouterr().out


def test_cli_run_goes_through_the_engine_runner_under_the_events_scope(tmp_path):
    """End to end as a subprocess: `ctf client-replay run` -> the runner -> the engine. The real pink
    profile's scope does not list loopback, so the client's URL is refused and nothing is contacted."""
    d = handout(tmp_path, "http://127.0.0.1:9/")
    # A clean environment: a platform URL another test left in os.environ would change which rule
    # refuses the URL (the platform rule instead of the scope rule).
    env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "LANG") if k in os.environ}
    env.update(CTF_WORKDIR=str(tmp_path / "work"), CTF_EVENT="pink", CTF_TESTING="1")
    r = subprocess.run([sys.executable, "-m", "ctf", "client-replay", "run", str(d), "--event", "pink",
                        "--head", HEAD, "--challenge-id", "19"],
                       cwd=paths.repo_root(), env=env, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    res = SolverResult.from_json(r.stdout.strip().splitlines()[-1])
    assert res.status == "unsure" and res.engine == "web.client_replay" and res.flags == ()
    assert [e.kind for e in res.evidence] == ["user-agent", "client-url-refused"]
    assert "outside event 'pink' rules.live_service_scope" in res.evidence[1].detail
    assert "replay not run" in res.notes and "challenge 19: 0 wrong answer(s) of 3" in res.notes
    rec, = [x for x in ledger.read(tmp_path / "work") if x["event"] == "engine.run"]
    assert rec["engine"] == "web.client_replay" and rec["status"] == "unsure" and rec["challenge_id"] == "19"


# ------------------------------------------------------------------------- fast lane, web_evidence

@pytest.fixture(scope="module")
def cfg():
    return _config.load()


def test_fastlane_hands_off_a_shipped_client_without_fetching(tmp_path, cfg):
    d = handout(tmp_path, "https://pink.example.org/")
    detail = {"name": "PINK OS", "category": "Steganography", "description": "Boot it and look around."}

    def no_fetch(url):
        raise AssertionError(f"the fast lane fetched {url}")

    r = fastlane.try_solve(detail, d / "files", cfg=cfg, fetch=no_fetch, online=True)
    assert r["klass"] == "client-replay" and r["flag"] is None and r["candidate"] is None
    assert UA in r["how"] and "https://pink.example.org/" in r["how"] and r["source"] == "data.img"
    assert "python -m ctf client-replay run" in r["instruction"]


def test_fastlane_ignores_stock_clients_and_keeps_its_other_classes_first(tmp_path, cfg):
    stock = handout(tmp_path, "https://pink.example.org/", ua="curl/8.5.0", name="stock")
    detail = {"name": "x", "category": "misc", "description": "nothing special"}
    assert fastlane.try_solve(detail, stock / "files", cfg=cfg, online=False) is None
    assert fastlane.try_shipped_client(detail, None) is None
    assert fastlane.try_shipped_client(detail, tmp_path / "missing") is None
    d = handout(tmp_path, "https://pink.example.org/")
    sanity = {"name": "Read the rules", "category": "sanity", "description": "read the rules page"}
    r = fastlane.try_solve(sanity, d / "files", cfg=cfg, online=False)
    assert r["klass"] == "sanity"                              # a matched class wins over the hand-off


def test_fastlane_says_when_it_read_only_part_of_the_handout(tmp_path, cfg, monkeypatch):
    d = handout(tmp_path, "https://pink.example.org/")
    detail = {"name": "x", "category": "misc", "description": "nothing special"}
    monkeypatch.setattr(fastlane, "CLIENT_SCAN_BYTES", 30000)
    r = fastlane.try_shipped_client(detail, d / "files")
    assert r is not None and "only the first 30000 bytes were read" in r["how"]
    monkeypatch.setattr(fastlane, "CLIENT_SCAN_BYTES", 1000)   # the client lies past the budget: no claim
    assert fastlane.try_shipped_client(detail, d / "files") is None


def test_fastlane_does_not_hand_off_a_user_agent_that_is_only_nearby(tmp_path, cfg):
    """A User-Agent passed by variable is found only `nearby` its header name: a weaker reading the
    lane does not stake a hand-off on (the engine still lists it)."""
    from ctf import clientreplay
    files = tmp_path / "nearby" / "files"
    files.mkdir(parents=True)
    src = (b'UA = "PinkBrowser/2.0"\nHOME = "https://pink.example.org/"\n' + b"#" * 300
           + b'\nheaders = {"User-Agent": UA}\n')
    (files / "client.py").write_bytes(src)
    found = clientreplay.harvest([files]).custom_user_agents()
    assert [(c.value, c.how) for c in found] == [("PinkBrowser/2.0", "nearby")]     # the harvest does see it
    detail = {"name": "x", "category": "misc", "description": "nothing special"}
    assert fastlane.try_shipped_client(detail, files) is None


def test_fastlane_names_a_handout_it_could_not_read(tmp_path, cfg, monkeypatch, caplog):
    from ctf import clientreplay
    d = handout(tmp_path, "https://pink.example.org/")

    def broken(paths, *, max_bytes):
        raise PermissionError(13, "Permission denied", str(d / "files" / "data.img"))

    monkeypatch.setattr(clientreplay, "harvest", broken)
    detail = {"name": "x", "category": "misc", "description": "nothing special"}
    with caplog.at_level("WARNING", logger="ctf.fastlane"):
        assert fastlane.try_shipped_client(detail, d / "files") is None
    msg, = [r.getMessage() for r in caplog.records if r.name == "ctf.fastlane"]
    assert "shipped-client check did not run" in msg and "Permission denied" in msg and "data.img" in msg


def test_web_evidence_reads_client_constants_from_a_delivery(tmp_path):
    d = handout(tmp_path, "https://pink.example.org/")
    files = web_evidence.load_paths([d / "files"])
    got = web_evidence.client_constants(files)
    assert [(c["value"], c["path"], c["stock"]) for c in got["user_agents"]] == [(UA, "data.img", False)]
    assert {c["value"]: c["near_ua"] for c in got["urls"]} == {"https://pink.example.org/": True,
                                                               "https://docs.example.org/manual": False}
    assert got["files"] == 2
