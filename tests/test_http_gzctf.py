"""The gzctf preset of the http platform, and the [http.refuse] step it needs, against a
stand-in in the shape of GZCTF's player API on 127.0.0.1 (tests/fake_gzctf.py).

GZCTF signs a player in with a cookie, takes a flag and judges it later (a submission's
number, then its status), and may want every flag encrypted to its own key, which flightdeck
does not do: then no flag may leave, and the player is told why. Nothing real is contacted.
"""

from __future__ import annotations

import asyncio
import dataclasses
import tomllib

import httpx
import pytest
from typer.testing import CliRunner

from ctf_flightdeck import http_cli
from ctf_flightdeck.core.model import ChallengeStatus, PendingKind
from ctf_flightdeck.run import RunOptions, prepare_run
from ctf_flightdeck.platform.http import HttpCaller, parse_config, plan, preset_text
from ctf_flightdeck.plugins.call import CallFailed
from ctf_flightdeck.preflight import check, http_token_env, load_profile, placeholder_url

from fake_ctfd import HANG_UP, Reply
from fake_gzctf import COOKIE, GAME, PUBLIC_KEY, FakeGZCTF, GTask, body, problem, sample
from fake_http import FakeSite
from fake_model import FakeModelServer
from test_event_run import Model, config, log, play, submit, wait_for
from test_http_event import event_file, http_warnings, lane_for

GZ = {"preset": "gzctf", "game": GAME}
runner = CliRunner()


def gz(fake: FakeGZCTF, token: str = COOKIE, **table_keys) -> HttpCaller:
    return HttpCaller(parse_config({**GZ, **table_keys}), fake.url, token)


def run(coroutine):
    return asyncio.run(coroutine)


def failure(coroutine) -> CallFailed:
    with pytest.raises(CallFailed) as caught:
        run(coroutine)
    return caught.value


def refused(config: object) -> str:
    with pytest.raises(ValueError) as caught:
        parse_config(config)
    return str(caught.value)


def no_wait(caller: HttpCaller) -> HttpCaller:
    async def instantly(_seconds: float) -> None:
        return None

    caller.sleep = instantly
    return caller


# ---------------------------------------------------------------------- the table


def test_the_gzctf_preset_is_the_table_its_file_writes():
    preset = parse_config(GZ)
    assert preset.preset == "gzctf" and preset.game == GAME
    assert preset.auth.kind == "cookie" and preset.auth.cookie == "GZCTF_Token"
    assert str(preset.list.request) == "GET /api/game/{game}/details" and preset.list.items.text == "$.challenges.*[*]"
    assert {name: path.text for name, path in preset.list.fields.items()} == {
        "name": "$.title", "category": "$.category", "points": "$.score", "solves": "$.solved"}
    assert str(preset.detail.request) == "GET /api/game/{game}/challenges/{ref}"
    assert {name: path.text for name, path in preset.detail.fields.items()} == {
        "description": "$.content", "file_urls": "$.context.url", "max_attempts": "$.limit", "instance": "$.type"}
    assert preset.detail.instance_values == ("StaticContainer", "DynamicContainer")
    assert str(preset.submit.request) == "POST /api/game/{game}/challenges/{ref}" and preset.submit.body == {"flag": "{flag}"}
    assert preset.submit.verdicts == {"Accepted": "correct", "WrongAnswer": "incorrect"} and preset.submit.status == {429: "rate_limited"}
    poll = preset.submit.poll
    assert str(poll.request) == "GET /api/game/{game}/challenges/{ref}/status/{submission}" and poll.pending == ("FlagSubmitted",)
    assert str(preset.solved.request) == "GET /api/game/{game}/details" and preset.solved.refs.text == "$.rank.solvedChallenges[*].id"
    assert str(preset.refuse.request) == "GET /api/config" and preset.refuse.path.text == "$.apiPublicKey"
    assert preset.files_auth is False


def test_the_gzctf_preset_without_a_game_is_refused_and_says_where_the_number_is():
    said = refused({"preset": "gzctf"})
    assert said == ("http.list.request has {game} in its path, and the table has no game: set http.game "
                    "(GZCTF: the game's number, as its address shows it: https://.../games/3)")


@pytest.mark.parametrize("refuse, said", [
    ({"request": ["GET", "/api/config"], "path": "$.key"}, "http.refuse.reason is required"),
    ({"path": "$.key", "reason": "no"}, "http.refuse.request is required"),
    ({"request": ["POST", "/api/config"], "path": "$.key", "reason": "no"}, "http.refuse.request: the method must be GET"),
    ({"request": ["GET", "https://elsewhere.example.test/config"], "path": "$.key", "reason": "no"}, "http.refuse.request: the path must start with /"),
    ({"request": ["GET", "/api/{ref}/config"], "path": "$.key", "reason": "no"}, "http.refuse.request: {ref} may not stand here"),
    ({"request": ["GET", "/api/config"], "path": "$..key", "reason": "no"}, "http.refuse.path must be a path into the answer"),
    ({"request": ["GET", "/api/config"], "path": "$.key", "reason": "two\nlines"}, "http.refuse.reason must be one line"),
    ({"request": ["GET", "/api/config"], "path": "$.key", "reason": "x" * 301}, "http.refuse.reason must be one line"),
    ({"request": ["GET", "/api/config"], "path": "$.key", "reason": "no", "header": "X"}, "http.refuse.header is not a key flightdeck knows"),
])
def test_a_refuse_table_is_checked_rule_by_rule(refuse, said):
    written_out = {**tomllib.loads(preset_text("gzctf")), "game": GAME}  # no preset under it, whose keys would fill the gaps
    assert parse_config(written_out).refuse is not None
    assert refused({**written_out, "refuse": refuse}).startswith(said)


def test_the_plan_says_the_refuse_request_goes_without_the_token_before_each_flag():
    lines = plan(parse_config(GZ))
    assert "refuse    GET /api/config, without your token: before each flag; a value at $.apiPublicKey means no flag is sent" in lines
    assert "list      GET /api/game/{game}/details, with your token (the GZCTF_Token cookie)" in lines
    assert "{game} is 3" in lines


# ---------------------------------------------------------------------- pull and solved


def test_a_pull_reads_the_board_by_category_and_each_challenges_detail_and_fetches_its_file_without_the_cookie(tmp_path):
    with FakeGZCTF(sample()) as fake:
        reply = run(gz(fake).pull(tmp_path))
        asset = fake.of("asset")
        details, challenge = fake.of("details"), fake.of("challenge")
    by_ref = {c["ref"]: c for c in reply.challenges}
    assert set(by_ref) == {"11", "12", "13"} and reply.problems == () and reply.notes == ()
    assert by_ref["11"] == {"ref": "11", "name": "Warm Up", "category": "Misc", "points": 50, "solves": 0, "description": "Read the note.",
                            "max_attempts": 0, "files": ["0000/note.txt"]}
    assert by_ref["12"]["category"] == "Web" and by_ref["12"]["max_attempts"] == 3 and by_ref["12"]["files"] == []
    assert (tmp_path / "0000" / "note.txt").read_bytes() == b"a synthetic handout\n"
    assert all(r.headers.get("cookie") == f"GZCTF_Token={COOKIE}" for r in details + challenge) and len(challenge) == 3
    assert len(asset) == 1 and "cookie" not in asset[0].headers  # an asset of the site is fetched with no sign-in


def test_the_solved_list_is_the_teams_own_row_of_the_scoreboard():
    with FakeGZCTF(sample()) as fake:
        assert run(gz(fake).solved()) == {"13"}


def test_a_cookie_the_site_does_not_know_fails_the_pull_with_the_status_and_never_shows_the_cookie(tmp_path):
    with FakeGZCTF(sample()) as fake:
        caught = failure(gz(fake, token="CfDJ8-some-other-ticket").pull(tmp_path))
    assert str(caught) == ("GET /api/game/{game}/details was answered with HTTP 401 (Unauthorized) "
                           "(is the token the right one for this event, and still valid?)")
    assert "CfDJ8" not in str(caught)


def test_a_game_the_site_does_not_have_names_the_game_key_to_fix(tmp_path):
    """The example profile says game = "1"; a site whose game is another number answers 404,
    and the bare status left the player guessing which part of the profile was wrong."""
    with FakeGZCTF(sample()) as fake:
        caught = failure(gz(fake, game="1").pull(tmp_path))
        right = run(gz(fake).solved())
    assert str(caught) == ('GET /api/game/{game}/details was answered with HTTP 404 (Not Found) (is game = "1" under [http] '
                           "this event's game? It is the number in the game's address on the site)")
    assert right == {"13"}


def test_a_challenge_gone_between_the_list_and_its_detail_does_not_blame_the_game(tmp_path):
    """The list was read from the game, so the game is right: one challenge's 404 (hidden or
    removed since) is that challenge's, and the pull names it without the game hint."""
    with FakeGZCTF(sample()) as fake:
        fake.script("challenge", problem(404, "Challenge not found"))
        reply = run(gz(fake).pull(tmp_path))
    assert len(reply.problems) == 1 and "HTTP 404 (Not Found)" in reply.problems[0], reply.problems
    assert "is game =" not in reply.problems[0]
    assert len(reply.challenges) == len(sample()) - 1


@pytest.mark.parametrize("pasted", [f"GZCTF_Token={COOKIE}", f"GZCTF_Token= {COOKIE}"])
def test_the_cookie_may_be_pasted_with_its_name_in_front(pasted):
    """A browser's tools copy a cookie as NAME=value; sent as it is, the site would be given GZCTF_Token=GZCTF_Token=..."""
    with FakeGZCTF(sample()) as fake:
        caller = gz(fake, token=pasted)
        assert caller.token == COOKIE and run(caller.solved()) == {"13"}


def test_the_cookies_name_with_no_value_after_it_is_refused_before_anything_is_sent():
    with FakeGZCTF(sample()) as fake:
        with pytest.raises(ValueError, match=r"holds the cookie's name \(GZCTF_Token=\) and no value after it"):
            gz(fake, token="GZCTF_Token=")
        assert fake.requests == []


# ---------------------------------------------------------------------- submit


def test_a_flag_is_sent_once_and_its_status_looked_at_until_it_is_judged():
    with FakeGZCTF(sample()) as fake:
        fake.pending = 2
        right = run(no_wait(gz(fake)).submit("11", "t{warm}"))
        wrong = run(no_wait(gz(fake)).submit("12", "t{nope}"))
        assert fake.submits() == [(11, "t{warm}"), (12, "t{nope}")]
        looks = [r.route for r in fake.of("status")]
    assert right.word == "correct" and wrong.word == "incorrect"
    assert looks == ["/api/game/3/challenges/11/status/901"] * 3 + ["/api/game/3/challenges/12/status/902"] * 3


def test_a_flag_for_a_challenge_already_solved_is_judged_correct_as_gzctf_judges_it():
    with FakeGZCTF(sample()) as fake:
        assert run(no_wait(gz(fake)).submit("13", "t{done}")).word == "correct"


def test_a_flag_still_unjudged_after_every_look_may_have_arrived_and_is_not_called_wrong():
    with FakeGZCTF(sample()) as fake:
        fake.pending = 100
        caught = failure(no_wait(gz(fake)).submit("11", "t{warm}"))
        assert len(fake.submits()) == 1 and len(fake.of("status")) == 15
    assert caught.timed_out and "had not judged it after 15 looks" in str(caught)


def test_a_rate_limit_is_a_rate_limit_with_the_wait_its_retry_after_names():
    with FakeGZCTF(sample()) as fake:
        fake.limited = 1
        verdict = run(gz(fake).submit("11", "t{warm}"))
        assert fake.of("status") == []
    assert verdict.word == "rate_limited" and verdict.retry_after == 5.0


@pytest.mark.parametrize("reply, said", [
    (problem(400, "Submission limit exceeded"), "HTTP 400, nothing at $: Submission limit exceeded"),
    (problem(404, "Challenge not found"), "HTTP 404, nothing at $: Challenge not found"),
])
def test_a_refusal_of_the_site_is_unjudged_with_its_own_words(reply, said):
    with FakeGZCTF(sample()) as fake:
        fake.script("submit", reply)
        verdict = run(gz(fake).submit("12", "t{web}"))
    assert (verdict.word, verdict.detail) == ("unjudged", said)


def test_not_found_at_the_status_is_no_verdict_and_the_flag_comes_back():
    with FakeGZCTF(sample()) as fake:
        fake.script("status", body("NotFound"))
        verdict = run(gz(fake).submit("11", "t{warm}"))
    assert verdict.word == "unjudged" and verdict.detail == 'HTTP 200, $ is "NotFound"'


def test_the_cookie_is_cut_out_of_what_the_site_says_back():
    with FakeGZCTF(sample()) as fake:
        fake.script("submit", problem(400, f"bad ticket {COOKIE}"))
        verdict = run(gz(fake).submit("11", "t{warm}"))
    assert COOKIE not in verdict.detail and "bad ticket" in verdict.detail


# ---------------------------------------------------------------------- a site that encrypts its flags


ENCRYPTS = ("flightdeck did not send the flag: this GZCTF site encrypts flags in the browser before they are sent (its ApiEncryption "
            "setting), which flightdeck does not do: submit the flag on the site (GET /api/config: $.apiPublicKey has a value)")


def test_no_flag_leaves_for_a_site_that_wants_flags_encrypted_and_the_player_is_told_why():
    with FakeGZCTF(sample()) as fake:
        fake.encrypted = True
        caught = failure(gz(fake).submit("11", "t{warm}"))
        assert fake.submits() == []
        config = fake.of("config")
    assert str(caught) == ENCRYPTS and not caught.timed_out
    assert len(config) == 1 and "cookie" not in config[0].headers  # the site's public settings are read without the cookie


def test_the_setting_is_read_again_before_each_flag():
    """A site may turn encryption on during the event: the flag after that is kept back."""
    with FakeGZCTF(sample()) as fake:
        caller = no_wait(gz(fake))
        assert run(caller.submit("11", "t{warm}")).word == "correct"
        fake.encrypted = True
        assert str(failure(caller.submit("12", "t{web}"))) == ENCRYPTS
        assert fake.submits() == [(11, "t{warm}")] and len(fake.of("config")) == 2


@pytest.mark.parametrize("reply", [Reply(500, {"title": "oops", "status": 500}), Reply(200, "<!doctype html><p>sign in"), HANG_UP])
def test_settings_that_cannot_be_read_keep_the_flag_back(reply):
    """Nobody knows whether the site would judge a flag sent in the clear: none is sent."""
    with FakeGZCTF(sample()) as fake:
        fake.script("config", reply)
        caught = failure(gz(fake).submit("11", "t{warm}"))
        assert fake.submits() == []
    assert str(caught).startswith("flightdeck could not tell whether the platform takes a flag as flightdeck sends it: ")
    assert not caught.timed_out


@pytest.mark.parametrize("value, keeps_back", [(None, False), ("", False), (False, False), ([], False), ({}, False),
                                               (PUBLIC_KEY, True), (0, True), (True, True)])
def test_what_counts_as_a_value_at_the_refuse_path(value, keeps_back):
    with FakeGZCTF(sample()) as fake:
        fake.script("config", body({"apiPublicKey": value}))
        if keeps_back:
            failure(no_wait(gz(fake)).submit("11", "t{warm}"))
            assert fake.submits() == []
        else:
            assert run(no_wait(gz(fake)).submit("11", "t{warm}")).word == "correct"


def test_a_pull_of_a_site_that_encrypts_its_flags_says_no_flag_is_sent_and_still_pulls(tmp_path):
    with FakeGZCTF(sample()) as fake:
        fake.encrypted = True
        reply = run(gz(fake).pull(tmp_path))
    assert len(reply.challenges) == 3
    assert reply.notes == (ENCRYPTS.replace("flightdeck did not send the flag: ", "no flag is sent from here: "),)


def test_a_pull_whose_settings_cannot_be_read_says_so_and_still_pulls(tmp_path):
    with FakeGZCTF(sample()) as fake:
        fake.script("config", Reply(503, b""))
        reply = run(gz(fake).pull(tmp_path))
    assert len(reply.challenges) == 3 and len(reply.notes) == 1
    assert reply.notes[0].endswith("HTTP 503 (Service Unavailable), not JSON; each flag asks again before it is sent")


def test_a_table_with_no_refuse_step_never_asks_for_one():
    with FakeGZCTF(sample()) as fake:
        fake.encrypted = True
        caller = HttpCaller(dataclasses.replace(parse_config(GZ), refuse=None), fake.url, COOKIE)
        run(no_wait(caller).submit("11", "t{warm}"))
        assert fake.of("config") == [] and len(fake.submits()) == 1


# ---------------------------------------------------------------------- the dry run, the example, pre-flight


def test_check_says_whether_flags_can_be_sent():
    with FakeGZCTF(sample()) as fake:
        fine = run(gz(fake).check())
        fake.encrypted = True
        kept = run(gz(fake).check())
        assert fake.submits() == []
    assert "refuse   GET /api/config: nothing at $.apiPublicKey, so flags can be sent" in fine.lines and fine.problems == 0
    assert any(line.startswith("refuse   no flag would be sent: this GZCTF site encrypts flags") for line in kept.lines)
    assert kept.problems == 1


@pytest.mark.parametrize("routes", [False, True])
def test_the_gzctf_example_profile_loads_and_passes_the_check(tmp_path, routes):
    result = runner.invoke(http_cli.app, ["example", "--preset", "gzctf", *(["--routes"] if routes else [])])
    assert result.exit_code == 0 and result.output == http_cli.example_profile(routes, "gzctf")
    path = tmp_path / "event.toml"
    path.write_text(result.output)
    loaded, chosen = load_profile(path)
    variable = "HTTP_TOKEN" if routes else "GZCTF_TOKEN"
    assert loaded.token_env == variable and loaded.http.game == "1" and (loaded.http.preset == "gzctf") is not routes
    assert [p.message for p in check(loaded, chosen, max_lanes=4, environ={variable: "set"}) if p.refuse] == [placeholder_url(loaded.url)]  # the address left as the example's: the one refusal (placeholder_url)
    preset = parse_config({"preset": "gzctf", "game": "1"})
    assert {**loaded.http.__dict__, "preset": None} == {**preset.__dict__, "preset": None}  # the routes written out are the preset's


def test_an_example_of_a_preset_flightdeck_does_not_have_is_refused():
    result = runner.invoke(http_cli.app, ["example", "--preset", "ctfx"])
    assert result.exit_code == 2 and "no preset of that name (known: rctf, rctf2, noctf, gzctf)" in result.output


@pytest.mark.parametrize("name, fine", [("GZCTF_TOKEN", True), ("GZCTF_TOKEN_FINALS", True), ("HTTP_TOKEN", True), ("RCTF_TOKEN", False),
                                        ("GZ_TOKEN", False)])
def test_the_token_variable_of_a_gzctf_profile_is_named_for_gzctf(name, fine):
    assert (http_token_env(name, parse_config(GZ), None, "https://ctf.example.test") is None) is fine


def test_a_site_answering_in_another_shape_is_named_by_the_check_not_guessed_at():
    """A site that is not GZCTF (or a version whose answer moved): the dry run names the path that matched nothing."""
    def other(request):
        if request.route == "/api/config":
            return body({"apiPublicKey": None})
        return body({"games": []})

    with FakeSite(other) as site:
        caught = failure(HttpCaller(parse_config(GZ), site.url, COOKIE).check())
    assert "list.items ($.challenges.*[*]) does not fit its answer: $.challenges is not in the answer" in str(caught)


# ---------------------------------------------------------------------- whole runs


def gz_run(tmp_path, fake: FakeGZCTF, server, monkeypatch):
    monkeypatch.setenv("GZCTF_TOKEN", COOKIE)
    event = event_file(tmp_path, fake.url, http=f'preset = "gzctf"\ngame = "{GAME}"', token_env="GZCTF_TOKEN",
                       board=str(tmp_path / "board"), pull="auto", submit="auto")
    return prepare_run(RunOptions(event=event, config=config(tmp_path, server.base_url, max_lanes=1)))


def test_a_run_plays_a_gzctf_game_from_the_preset_and_the_flag_is_judged_after_it_is_taken(tmp_path, monkeypatch):
    with FakeGZCTF(sample()[:1] + sample()[2:]) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        run = gz_run(tmp_path, fake, server, monkeypatch)
        assert run.plug.refs == {"warm-up": "11", "done-before": "13"}

        async def body(run):
            assert run.deck.challenges["done-before"].status is ChallengeStatus.TEAMMATE
            await wait_for(lambda: run.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run, body)
        assert fake.submits() == [(11, "t{warm}")] and len(fake.of("status")) == 2
    assert [(e["data"]["flag"], e["data"]["correct"]) for e in log(run) if e["kind"] == "submit"] == [("t{warm}", True)]
    everything = run.log.path.read_text() + "\n".join(run.notes()) + (run.dir / "status.json").read_text()
    assert COOKIE not in everything


def test_a_run_on_a_site_that_encrypts_its_flags_gives_the_flag_to_the_player_with_the_reason(tmp_path, monkeypatch):
    with FakeGZCTF(sample()[:1]) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        fake.encrypted = True
        run = gz_run(tmp_path, fake, server, monkeypatch)
        assert any("no flag is sent from here: this GZCTF site encrypts flags" in note for note in run.notes())

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_for(run, "warm-up").pending is not None, "the flag, back with the player")
            assert lane_for(run, "warm-up").pending.kind is PendingKind.CONFIRM

        play(run, body)
        assert fake.submits() == []
    assert any(ENCRYPTS in text for text in http_warnings(run))
    assert run.deck.challenges["warm-up"].status is not ChallengeStatus.SOLVED


def test_the_fake_serves_files_from_where_gzctf_keeps_them():
    """The fake's own shape, so the pull test above means what it says."""
    task = GTask(1, "A", files={"a.bin": b"\x00\x01"})
    with FakeGZCTF([task]) as fake:
        listed = httpx.get(f"{fake.url}/api/game/3/challenges/1", cookies={"GZCTF_Token": COOKIE}).json()
        assert listed["context"]["url"].startswith("/assets/") and listed["context"]["url"].endswith("/a.bin")
        assert httpx.get(fake.url + listed["context"]["url"]).content == b"\x00\x01"
