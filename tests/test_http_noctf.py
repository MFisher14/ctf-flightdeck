"""The noCTF preset of the http platform (platform/http_presets/noctf.toml), against a stand-in
in the shape of noCTF's public source (tests/fake_http.py, FakeNoCTF).

The engine's rules are tested in test_http_platform.py and an event's in test_http_event.py,
against rCTF's shape. Here: that the preset's routes are noCTF's (a bearer token, a list with
no text and a detail route for it, files under the API's address with no token, a flag in
{"data": ...}, the verdict in data.status and the errors by their HTTP status, the team's
solves) and that a run plays an event through it. Nothing real is contacted.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from ctf_flightdeck import http_cli
from ctf_flightdeck.core.model import ChallengeStatus, LaneState, PendingKind
from ctf_flightdeck.platform.http import PRESETS, HttpCaller, parse_config, plan, preset_text
from ctf_flightdeck.plugins.call import Verdict
from ctf_flightdeck.preflight import check, describe, load_profile
from ctf_flightdeck.run import RunOptions, prepare_run

from fake_ctfd import Reply
from fake_http import NOCTF_SESSION, FakeNoCTF, NTask, noctf_sample
from fake_model import FakeModelServer
from test_event_run import Model, config, log, model_api, play, platform_solves, submit, wait_for  # noqa: F401
from test_http_event import event_file, http_warnings, invoke, lane_for, own_config  # noqa: F401

NOCTF = {"preset": "noctf"}
TOKEN_VAR = "NOCTF_TOKEN"
PRESET = 'preset = "noctf"'
URL = "https://api.ctf.example.test"


def noctf(fake: FakeNoCTF, **table_keys) -> HttpCaller:
    return HttpCaller(parse_config({**NOCTF, **table_keys}), fake.url, fake.session)


def run(coroutine):
    return asyncio.run(coroutine)


# ---------------------------------------------------------------------- the table


def test_the_noctf_preset_is_the_table_its_file_writes_and_a_key_of_the_profile_wins():
    preset = parse_config(NOCTF)
    assert "noctf" in PRESETS and preset.preset == "noctf" and preset.variable_example == "NOCTF_TOKEN"
    assert preset.auth.kind == "bearer" and preset.auth.request is None and preset.files_auth is False
    assert str(preset.list.request) == "GET /challenges" and preset.list.items.text == "$.data.challenges[*]"
    assert preset.list.ref.text == "$.id"
    assert {name: path.text for name, path in preset.list.fields.items()} == {
        "name": "$.title", "category": "$.tags.categories", "points": "$.value", "solves": "$.solve_count"}
    assert str(preset.detail.request) == "GET /challenges/{ref}"
    assert {name: path.text for name, path in preset.detail.fields.items()} == {
        "description": "$.data.description", "file_urls": "$.data.metadata.files[*].url",
        "file_names": "$.data.metadata.files[*].filename"}
    assert str(preset.submit.request) == "POST /challenges/{ref}/solves" and preset.submit.body == {"data": "{flag}"}
    assert preset.submit.verdict_path.text == "$.data.status" and preset.submit.detail_path.text == "$.message"
    assert preset.submit.verdicts == {"correct": "correct", "incorrect": "incorrect"}  # queued and invalid: no verdict
    assert preset.submit.status == {429: "rate_limited"}  # 409 is solved or queued: no verdict
    assert str(preset.solved.request) == "GET /team/scoreboard" and preset.solved.refs.text == "$.data.solves[*].challenge_id"
    own = parse_config({**NOCTF, "submit": {"status": {"409": "already_solved"}}})
    assert own.submit.status == {429: "rate_limited", 409: "already_solved"} and own.submit.verdicts == preset.submit.verdicts


def test_the_preset_file_says_it_was_tried_against_a_stand_in_only():
    text = preset_text("noctf")
    assert "github.com/noctf-project/noctf" in text and "nobody has played a real noCTF" in text


def test_the_plan_says_the_session_token_goes_as_a_bearer_token_and_files_go_without_it():
    lines = plan(parse_config(NOCTF))
    assert lines[0] == "the noctf preset's routes, with the [http] table's own keys on top"
    assert "list      GET /challenges, with your token (Authorization: Bearer)" in lines
    assert "submit    POST /challenges/{ref}/solves, with your token (Authorization: Bearer): the flag in the request's body, sent once" in lines
    assert "solved    GET /team/scoreboard, with your token (Authorization: Bearer)" in lines
    assert any(line.startswith("files     each address at $.data.metadata.files[*].url: on the event's own address without your token")
               for line in lines)


# ---------------------------------------------------------------------- the three calls


def test_a_pull_lists_once_asks_each_new_challenge_for_its_text_and_fetches_a_file_without_the_token(tmp_path):
    with FakeNoCTF(noctf_sample()) as fake:
        reply = run(noctf(fake).pull(tmp_path))
        assert fake.kinds() == ["list", "detail", "file", "detail", "detail"]
        assert all(r.headers["authorization"] == f"Bearer {NOCTF_SESSION}" for r in fake.requests if r.route != "/files/local/r11-note.txt")
        (upload,) = fake.of("file")
        assert "authorization" not in upload.headers and "cookie" not in upload.headers
        assert upload.path == "/files/local/r11-note.txt?iat=1&sig=c2ln"  # the signed path, under the API's address
    assert reply.problems == ()
    assert reply.challenges == (
        {"ref": "11", "name": "Warm Up", "category": "misc", "points": 50, "solves": 0, "description": "Read the note.",
         "files": ["0000/note.txt"]},
        {"ref": "12", "name": "Two Hats", "category": "crypto,rev", "solves": 3, "description": "A synthetic challenge.", "files": []},
        {"ref": "13", "name": "Done Before", "category": "misc", "points": 150, "solves": 9, "description": "A synthetic challenge.",
         "files": []},
    )
    assert (tmp_path / "0000" / "note.txt").read_bytes() == b"a synthetic handout\n"


def test_a_challenge_on_the_board_already_is_not_asked_for_again(tmp_path):
    with FakeNoCTF(noctf_sample()) as fake:
        reply = run(noctf(fake).pull(tmp_path, known=["11", "12", "13"]))
        assert fake.kinds() == ["list"]
    assert [c["ref"] for c in reply.challenges] == ["11", "12", "13"] and all("description" not in c for c in reply.challenges)


def test_a_challenge_with_no_category_tag_lands_on_the_board_as_any_other(tmp_path):
    with FakeNoCTF([NTask(21, "Plain", categories=None)]) as fake:
        reply = run(noctf(fake).pull(tmp_path))
    assert reply.problems == () and [c["name"] for c in reply.challenges] == ["Plain"] and "category" not in reply.challenges[0]


def test_a_token_noctf_refuses_is_a_failure_that_names_its_answer_and_never_shows_the_token(tmp_path):
    with FakeNoCTF(noctf_sample()) as fake:
        engine = HttpCaller(parse_config(NOCTF), fake.url, "fake-expired-session-0000")
        with pytest.raises(Exception) as failed:
            run(engine.pull(tmp_path))
    said = str(failed.value)
    assert "GET /challenges was answered with HTTP 401" in said and "no authorization header supplied" in said
    assert "fake-expired-session-0000" not in said


def test_noctfs_verdicts_are_its_status_and_its_errors_are_read_by_their_http_status():
    with FakeNoCTF(noctf_sample()) as fake:
        engine = noctf(fake)
        assert run(engine.submit("11", "t{nope}")) == Verdict("incorrect", "")
        assert run(engine.submit("11", "t{warm}")) == Verdict("correct", "")
        fake.limited, fake.retry_after = 1, 12
        assert run(engine.submit("12", "t{hats}")) == Verdict("rate_limited", "You're trying too hard", None, 12.0)
        assert fake.submits() == [("11", "t{nope}"), ("11", "t{warm}"), ("12", "t{hats}")]
        assert all(r.json == {"data": r.json["data"]} and r.headers["authorization"] == f"Bearer {NOCTF_SESSION}"
                   for r in fake.of("solve"))


@pytest.mark.parametrize("setup, ref, said", [
    # solved already, by the team: noCTF's 409 says the same for a flag still queued, so it is no verdict
    (lambda fake: None, "13", 'HTTP 409, nothing at $.data.status: A current (queued or solved) submission exists'),
    (lambda fake: setattr(fake, "ended", True), "11", "HTTP 403, nothing at $.data.status: The CTF has ended. Thanks for playing!"),
    (lambda fake: None, "99", "HTTP 404, nothing at $.data.status: Challenge not found"),
    (lambda fake: setattr(fake.tasks[11], "manual", True), "11", 'HTTP 200, $.data.status is "queued"'),
    (lambda fake: fake.script("solve", Reply(200, {"data": {"status": "invalid", "hidden": False}})), "11",
     'HTTP 200, $.data.status is "invalid"'),
])
def test_what_noctf_answers_that_is_not_correct_or_incorrect_is_no_verdict_and_never_wrong(setup, ref, said):
    with FakeNoCTF(noctf_sample()) as fake:
        setup(fake)
        assert run(noctf(fake).submit(ref, "t{warm}")) == Verdict("unjudged", said)
        assert len(fake.of("solve")) == 1  # sent once


def test_the_solved_list_is_the_teams_solves_by_challenge_id():
    with FakeNoCTF(noctf_sample()) as fake:
        engine = noctf(fake)
        assert run(engine.solved()) == {"13"}
        fake.tasks[11].solved = True
        assert run(engine.solved()) == {"11", "13"}
        assert fake.kinds() == ["team", "team"]


# ---------------------------------------------------------------------- the profile and the commands


def noctf_file(tmp_path: Path, url: str = URL, **fields) -> Path:
    return event_file(tmp_path, url, http=PRESET, token_env=fields.pop("token_env", TOKEN_VAR), **fields)


def test_a_noctf_profile_takes_a_token_variable_named_for_noctf_and_prints_its_plan(tmp_path):
    loaded, chosen = load_profile(noctf_file(tmp_path))
    assert [p.message for p in check(loaded, chosen, max_lanes=4, environ={TOKEN_VAR: "set"}) if p.refuse] == []
    lines = describe(loaded, chosen, environ={TOKEN_VAR: "set"})
    assert lines[0] == f"event     Fake Quals · http (noctf preset) at {URL} · solo"
    assert f"token     ${TOKEN_VAR} (set), sent only to {URL}" in lines
    other = tmp_path / "other"
    other.mkdir()
    wrong, chosen = load_profile(noctf_file(other, token_env="RCTF_TOKEN"))  # rCTF's variable is not noCTF's
    refusals = [p.message for p in check(wrong, chosen, max_lanes=4, environ={"RCTF_TOKEN": "set"}) if p.refuse]
    assert len(refusals) == 1 and refusals[0].startswith("event.token_env names RCTF_TOKEN, a variable that is not named for this platform")
    assert refusals[0].endswith("like NOCTF_TOKEN")


@pytest.mark.parametrize("routes", [False, True])
def test_the_noctf_example_profile_loads_and_passes_the_check(tmp_path, routes):
    result = invoke("example", "--preset", "noctf", *(["--routes"] if routes else []))
    assert result.exit_code == 0 and result.output == http_cli.example_profile(routes, "noctf")
    path = tmp_path / "event.toml"
    path.write_text(result.output)
    loaded, chosen = load_profile(path)
    variable = "HTTP_TOKEN" if routes else TOKEN_VAR
    assert loaded.token_env == variable and (loaded.http.preset == "noctf") is not routes
    assert [p.message for p in check(loaded, chosen, max_lanes=4, environ={variable: "set"}) if p.refuse] == []
    assert {**loaded.http.__dict__, "preset": None} == {**parse_config(NOCTF).__dict__, "preset": None}  # the routes written out are the preset's
    assert ("noctf-session-token" in result.output) is not routes and ("These are noCTF's, written out" in result.output) is routes


def test_the_example_with_no_preset_named_is_rctfs_and_an_unknown_preset_is_refused_by_name():
    assert invoke("example").output == http_cli.example_profile(False, "rctf") and 'preset = "rctf"' in invoke("example").output
    result = invoke("example", "--preset", "gzctf")
    assert result.exit_code != 0 and "no preset of that name (known: rctf, noctf)" in result.output


def test_http_check_against_noctf_shows_the_detail_route_and_submits_nothing(tmp_path, own_config, monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, NOCTF_SESSION)
    with FakeNoCTF(noctf_sample()) as fake:
        result = invoke("check", noctf_file(tmp_path, fake.url), "--show", "1")
        assert fake.kinds() == ["list", "detail", "team"] and fake.submits() == []
    assert result.exit_code == 0, result.output
    out = result.stdout.splitlines()
    assert "list     GET /challenges: HTTP 200, $.data.challenges[*] matched 3 challenges" in out
    assert "    detail  GET /challenges/{ref}: HTTP 200" in out
    assert "solved   GET /team/scoreboard: HTTP 200, $.data.solves[*].challenge_id matched 1 ref, 1 of them on the list" in out
    assert out[-1] == "every path a pull needs matched; nothing was submitted" and NOCTF_SESSION not in result.output


# ---------------------------------------------------------------------- a whole run


def noctf_run(tmp_path: Path, fake: FakeNoCTF, server):
    path = config(tmp_path, server.base_url, max_lanes=1)
    event = noctf_file(tmp_path, fake.url, board=str(tmp_path / "board"), pull="auto", submit="auto")
    return prepare_run(RunOptions(event=event, config=path))


def test_a_run_plays_a_noctf_event_from_the_preset_and_a_wrong_flag_is_wrong_and_the_right_one_solves(tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, NOCTF_SESSION)
    tasks = noctf_sample()[::2]  # Warm Up and Done Before: one lane
    with FakeNoCTF(tasks) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{nope}"), submit("t{warm}")]})) as server:
        run_ = noctf_run(tmp_path, fake, server)
        assert fake.kinds() == ["list", "detail", "file", "detail", "team"]
        board = tmp_path / "board"
        assert (board / "warm-up" / "note.txt").read_bytes() == b"a synthetic handout\n"
        assert run_.plug.refs == {"warm-up": "11", "done-before": "13"}

        async def body(run_):
            assert run_.deck.challenges["done-before"].status is ChallengeStatus.TEAMMATE
            await wait_for(lambda: run_.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run_, body)
        assert fake.submits() == [("11", "t{nope}"), ("11", "t{warm}")]
    submitted = [(e["data"]["flag"], e["data"]["correct"], e["data"]["by"]) for e in log(run_) if e["kind"] == "submit"]
    assert submitted == [("t{nope}", False, "platform"), ("t{warm}", True, "platform")]
    assert platform_solves(run_) == [("done-before", "your account", True)]
    assert lane_for(run_, "warm-up").state is LaneState.SOLVED and http_warnings(run_) == [] and run_.errors == []
    everything = run_.log.path.read_text() + "\n".join(run_.notes()) + (run_.dir / "status.json").read_text()
    assert NOCTF_SESSION not in everything and NOCTF_SESSION not in (board / "plugin.json").read_text()
    assert json.loads((board / "warm-up" / "challenge.json").read_text())["description"] == "Read the note."


def test_a_flag_noctf_queues_for_the_organisers_comes_back_to_the_player_and_is_never_wrong(tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, NOCTF_SESSION)
    tasks = [NTask(31, "By Hand", manual=True, flag="t{hand}")]
    with FakeNoCTF(tasks) as fake, FakeModelServer(responder=Model({"By Hand": [submit("t{hand}")]})) as server:
        run_ = noctf_run(tmp_path, fake, server)

        async def body(run_):
            await wait_for(lambda: run_.deck.lanes and lane_for(run_, "by-hand").pending is not None, "the flag, back with the player")
            assert lane_for(run_, "by-hand").pending.kind is PendingKind.CONFIRM

        play(run_, body)
        assert fake.submits() == [("31", "t{hand}")]
    assert http_warnings(run_) == ['the http adapter did not judge t{hand} for By Hand: the platform gave no verdict on it '
                                   '(HTTP 200, $.data.status is "queued")']
    assert not any(e["kind"] == "submit" and e["data"].get("correct") is False for e in log(run_))
