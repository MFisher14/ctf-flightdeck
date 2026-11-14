"""The http platform's engine (platform/http.py): the [http] table's rules, the paths into an
answer, and the three calls against stand-in servers on 127.0.0.1 (tests/fake_http.py).

Each rule that keeps a table from a teammate safe has a test here that fails when the rule is
dropped: one origin, the closed set of placeholders, where the token goes, what counts as a
verdict. Nothing real is contacted, and every file is written under tmp_path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import quote

import pytest

from ctf_flightdeck.platform import http as engine
from ctf_flightdeck.platform.http import HttpCaller, parse_config, parse_path, plan
from ctf_flightdeck.plugins.call import CallFailed, PlatformCaller, Verdict

from fake_ctfd import HANG_UP, Reply, make_tls
from fake_http import AUTH_TOKEN, TEAM_TOKEN, FakeRCTF, FakeSite, RTask, answer, login_link, sample
from serving import closed_port

RCTF = {"preset": "rctf"}
TOKEN = "fake-site-token-for-tests-3c9e"  # synthetic: the token of the tables that are not rCTF's


def table(**changes) -> dict:
    """A small table for a made-up platform (a bearer token, three routes); `changes` replace
    its tables or, with a dotted key ("submit.body"), one key inside one."""
    out = {
        "auth": {"kind": "bearer"},
        "list": {"request": ["GET", "/api/tasks"], "items": "$.tasks[*]", "ref": "$.id", "name": "$.title"},
        "submit": {"request": ["POST", "/api/tasks/{ref}/flag"], "body": {"flag": "{flag}"}, "verdict_path": "$.status",
                   "verdicts": {"ok": "correct", "bad": "incorrect"}},
        "solved": {"request": ["GET", "/api/solved"], "refs": "$.ids[*]"},
    }
    for key, value in changes.items():
        head, _, rest = key.partition(".")
        if rest:
            out[head] = {**out[head], rest: value}
        elif value is None:
            out.pop(head, None)
        else:
            out[head] = value
    return out


def caller(site, config: dict | None = None, token: str = TOKEN, **options) -> HttpCaller:
    return HttpCaller(parse_config(table() if config is None else config), site.url, token, **options)


def rctf(fake: FakeRCTF, **table_keys) -> HttpCaller:
    return HttpCaller(parse_config({**RCTF, **table_keys}), fake.url, fake.team_token)


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


# ---------------------------------------------------------------------- paths into an answer


DOC = {"data": [{"id": "a", "files": [{"url": "/u1"}, {"url": "/u2"}]}, {"id": "b", "files": []}], "odd key": {"x": 1}, "n": [10, 20, 30]}


@pytest.mark.parametrize("path, found", [
    ("$", [DOC]),
    ("$.data[*].id", ["a", "b"]),
    ("$.data.*.id", ["a", "b"]),
    ("$.data[0].files[*].url", ["/u1", "/u2"]),
    ("$.data[*].files[*].url", ["/u1", "/u2"]),
    ("$['odd key'].x", [1]),
    ('$["odd key"].x', [1]),
    ("$.n[-1]", [30]),
    ("$.n[3]", []),  # past the end
    ("$.data.id", []),  # a name of a list
    ("$.missing[*]", []),
    ("$.n[*].x", []),  # a name of a number
])
def test_a_path_matches_what_the_subset_of_jsonpath_says(path, found):
    assert parse_path("p", path).find(DOC) == found


@pytest.mark.parametrize("path", ["data.id", "", "$..id", "$.data[?(@.id)]", "$.data[0:2]", "$.length()", "$.a b", "$[x]", 7,
                                  "$" + ".a" * 17])
def test_a_path_outside_the_subset_is_refused_by_name(path):
    with pytest.raises(ValueError, match=r"^http\.list\.ref "):
        parse_path("http.list.ref", path)


@pytest.mark.parametrize("path", ["$['tok‮neg']", '$["a\u009b2J"]', "$['a​b']", "$['a\x7f']", "$['a⁦b']"])
def test_a_quoted_name_that_does_not_show_as_itself_is_refused(path):
    """The pre-flight and `http check` print a path as the table writes it: a bidi override,
    a C1 control (\\x9b starts a terminal's control sequence) or a zero-width character would
    make that line read as something it is not."""
    with pytest.raises(ValueError, match=r"^http\.auth\.token_path: a quoted name holds a control or invisible character") as caught:
        parse_path("http.auth.token_path", path)
    assert path[3:-2] not in str(caught.value)
    assert parse_path("p", "$['café key']").find({"café key": 1}) == [1]  # a name that shows as itself is fine


def test_a_missing_list_is_told_from_an_empty_one():
    """A key that is not there is the wrong answer; a list that is there and empty is an answer."""
    path = parse_path("p", "$.data[*].id")
    assert path.shaped({"data": []}) is None and path.find({"data": []}) == []
    assert path.shaped({"kind": "oops"}) == "$.data is not in the answer"
    assert path.shaped({"data": "soon"}) == "$.data is a string in the answer, not a list"


# ---------------------------------------------------------------------- the table


def test_the_rctf_preset_is_the_table_its_file_writes_and_a_key_of_the_profile_wins():
    preset = parse_config(RCTF)
    assert preset.preset == "rctf" and preset.auth.kind == "exchange" and str(preset.auth.request) == "POST /api/v1/auth/login"
    assert preset.auth.body == {"teamToken": "{token}"} and preset.auth.token_path.text == "$.data.authToken"
    assert str(preset.list.request) == "GET /api/v1/challs" and preset.list.items.text == "$.data[*]"
    assert {name: path.text for name, path in preset.list.fields.items()} == {
        "name": "$.name", "category": "$.category", "points": "$.points", "solves": "$.solves", "description": "$.description",
        "file_urls": "$.files[*].url", "file_names": "$.files[*].name"}
    assert str(preset.submit.request) == "POST /api/v1/challs/{ref}/submit" and preset.submit.body == {"flag": "{flag}"}
    assert preset.submit.verdicts == {"goodFlag": "correct", "badFlag": "incorrect", "badAlreadySolvedChallenge": "already_solved",
                                      "badRateLimit": "rate_limited"}
    assert preset.submit.status == {} and preset.submit.retry_after_unit == "ms" and preset.files_auth is False
    assert str(preset.solved.request) == "GET /api/v1/users/me" and preset.solved.refs.text == "$.data.solves[*].id"
    own = parse_config({**RCTF, "files_auth": True, "list": {"request": ["GET", "/api/v2/challs"]},
                        "submit": {"verdicts": {"badFlag": "unjudged", "goodFlagLate": "correct"}}})
    assert str(own.list.request) == "GET /api/v2/challs" and own.list.items.text == "$.data[*]"  # the rest of the table stays
    assert own.submit.verdicts["badFlag"] == "unjudged" and own.submit.verdicts["goodFlagLate"] == "correct"
    assert own.submit.verdicts["goodFlag"] == "correct" and own.files_auth is True


def test_a_checked_table_can_be_hashed_and_compared_as_the_rest_of_a_profile_is():
    assert hash(parse_config(RCTF)) == hash(parse_config(RCTF)) and parse_config(RCTF) == parse_config(RCTF)
    assert parse_config(RCTF) != parse_config({**RCTF, "files_auth": True})
    assert parse_config(RCTF) != parse_config({**RCTF, "submit": {"verdicts": {"badFlag": "unjudged"}}})


def test_a_preset_flightdeck_does_not_have_is_refused_and_its_name_is_not_shown():
    said = refused({"preset": "s3cr3t-pasted-here"})
    assert said.startswith("http.preset is not a preset flightdeck has (known: rctf)") and "s3cr3t" not in said


@pytest.mark.parametrize("config, said", [
    ("routes", "http must be a table ([http])"),
    ({}, 'http needs [http.auth], [http.list], [http.solved] (or preset = "rctf", which has them)'),
    (table(solved=None), 'http needs [http.solved] (or preset = "rctf", which has them)'),
    ({**table(), "headers": {"X-Evil": "1"}}, "http.headers is not a key flightdeck knows (known in [http]: preset, game, files_auth, auth, "
                                              "list, detail, submit, solved)"),
    (table(**{"list.next_path": "$.next"}), "http.list.next_path: pages of a listing is not something the http platform does yet; a plugin "
                                            "can (docs/PLUGINS.md)"),
    (table(**{"submit.form": {"flag": "{flag}"}}), "http.submit.form: a form-encoded body is not something the http platform does yet; a "
                                                   "plugin can (docs/PLUGINS.md)"),
    (table(**{"auth.csrf_header": "X-CSRFToken"}), "http.auth.csrf_header: a CSRF header is not something the http platform does yet; a "
                                                   "plugin can (docs/PLUGINS.md)"),
    (table(list={"request": ["GET", "/x"], "items": "$[*]", "ref": "$.id"}), "http.list.name is required"),
    (table(**{"list.file_names": "$.files[*].name"}), "http.list.file_names names the files of http.list.file_urls, which is missing"),
    (table(files_auth="yes"), "http.files_auth must be true or false: whether a file on the event's own address is asked for with the token"),
    (table(**{"list.request": ["GET", "/api/{game}/tasks"]}), "http.list.request has {game} in its path, and the table has no game: set http.game"),
    (table(**{"submit.body": {"flag": "{flag}", "event": "{game}"}}), "http.submit.body has {game} in it, and the table has no game: set http.game"),
])
def test_a_table_that_is_not_one_is_refused_by_the_key(config, said):
    assert refused(config) == said


@pytest.mark.parametrize("route", [
    ["GET", "https://evil.example.test/api/tasks"],  # a whole URL: another host
    ["GET", "//evil.example.test/api/tasks"],  # a host with no scheme
    ["GET", "api/tasks"],  # not under the root
    ["GET", "/api/../admin"],
    ["GET", "/api\\tasks"],
    ["GET", "/api/tasks#frag"],
    ["GET", "/api/tasks@evil.example.test"],
    ["GET", "/api/ tasks"],
    ["GET", "/" + "a" * 200],
])
def test_a_route_is_a_path_under_the_events_address_and_nothing_else(route):
    """One origin: no table can name a host for the token to go to."""
    assert refused(table(**{"list.request": route})) == (
        "http.list.request: the path must start with / and name a route under event.url: no scheme, no host, no .. "
        "(letters, digits and _ . / ? = & ~ - only)")


@pytest.mark.parametrize("where, route, said", [
    ("list.request", ["POST", "/api/tasks"], "http.list.request: the method must be GET"),
    ("solved.request", ["DELETE", "/api/solved"], "http.solved.request: the method must be GET"),
    ("submit.request", ["GET", "/api/tasks/{ref}/flag"], "http.submit.request: the method must be POST or PUT or PATCH"),
    ("list.request", "GET /api/tasks", 'http.list.request must be [METHOD, PATH], such as ["GET", "/api/..."]'),
    ("list.request", ["GET", "/api/tasks?t={token}"],
     "http.list.request: {token} may not stand here: the token goes only where [http.auth] says (here: {game})"),
    ("submit.request", ["POST", "/api/tasks/{ref}/flag?f={flag}"],
     "http.submit.request: {flag} may not stand here: a flag goes in the body, never in an address (here: {ref}, {game})"),
    ("list.request", ["GET", "/api/tasks/{ref}"], "http.list.request: {ref} may not stand here (here: {game})"),
    ("submit.request", ["POST", "/api/{name}/flag/{ref}"],
     "http.submit.request: {name} is not a placeholder flightdeck knows (here: {ref}, {game})"),
    ("submit.request", ["POST", "/api/{ref}/{"], "http.submit.request: a { or } that is not one of flightdeck's placeholders"),
])
def test_a_request_takes_only_the_methods_and_placeholders_of_its_kind(where, route, said):
    """A closed set of placeholders: nothing of a challenge but its ref can be put into a request."""
    assert refused(table(**{where: route})) == said


@pytest.mark.parametrize("changes, said", [
    ({"submit.body": {"flag": "{flag}", "auth": "{token}"}},
     "http.submit.body: {token} may not stand here: the token goes only where [http.auth] says (here: {ref}, {flag}, {game})"),
    ({"submit.body": {"answer": "x"}}, "http.submit.body must have {flag} in one of its values: where the flag goes"),
    ({"submit.request": ["POST", "/api/flag"]},
     "http.submit must say which challenge the flag is for: {ref} in the request's path or in the body"),
    ({"submit.body": {"flag": "{flag}", "id": "n-{ref:int}"}},
     "http.submit.body: only {ref:int} takes a kind, and only as a body's whole value (the ref as a JSON number)"),
    ({"submit.body": {"flag": "{flag}", "id": "{flag:int}"}},
     "http.submit.body: only {ref:int} takes a kind, and only as a body's whole value (the ref as a JSON number)"),
    ({"submit.body": {"flag": "{flag}", "name": "{challenge}"}},
     "http.submit.body: {challenge} is not a placeholder flightdeck knows (here: {ref}, {flag}, {game})"),
    ({"submit.verdicts": {"ok": "accepted"}},
     "http.submit.verdicts: a rule's verdict must be one of correct, incorrect, already_solved, rate_limited, unjudged"),
    ({"submit.status": {"teapot": "incorrect"}}, "http.submit.status: a rule's key must be an HTTP status, 100 to 599"),
    ({"submit.verdicts": {}}, "http.submit needs a rule that reads the answer: [http.submit.verdicts] (with verdict_path) or "
                              "[http.submit.status]. With none, no flag would ever be judged"),
    ({"submit": {"request": ["POST", "/api/tasks/{ref}/flag"], "body": {"flag": "{flag}"}, "verdicts": {"ok": "correct"}}},
     "http.submit.verdicts needs http.submit.verdict_path: where the answer holds the value the rules look at"),
    ({"submit.retry_after_unit": "minutes"}, 'http.submit.retry_after_unit must be "s" or "ms"'),
    ({"submit.poll": {"request": ["GET", "/api/status"], "id_path": "$", "pending": ["queued"]}},
     "http.submit.poll.request must say which submission it looks at: {submission} in its path"),
    ({"submit.poll": {"request": ["GET", "/api/status/{submission}"], "id_path": "$", "pending": []}},
     "http.submit.poll.pending must be a list of the values that mean the platform has not judged the flag yet"),
    ({"submit.poll": {"request": ["GET", "/api/status/{submission}"], "id_path": "$", "pending": ["queued"], "at_most": 500}},
     "http.submit.poll.at_most must be a whole number from 1 to 30: how many looks"),
    ({"submit.poll": {"request": ["GET", "/api/status/{submission}"], "id_path": "$", "pending": ["queued"], "every": 0}},
     "http.submit.poll.every must be a number of seconds from 0.2 to 30"),
])
def test_a_submit_table_must_say_where_the_flag_goes_and_how_the_answer_is_read(changes, said):
    assert refused(table(**changes)) == said


@pytest.mark.parametrize("auth, said", [
    ({"kind": "password"}, "http.auth.kind must be one of bearer, token, header, cookie, exchange"),
    ({"kind": "header"}, "http.auth.header must be the name of the header that carries the token (letters, digits and -), and not one "
                         "that means something else to a server (Host, Cookie, Content-Type, ...)"),
    ({"kind": "header", "header": "Host"}, "http.auth.header must be the name of the header that carries the token (letters, digits and "
                                           "-), and not one that means something else to a server (Host, Cookie, Content-Type, ...)"),
    ({"kind": "header", "header": "X-Key\r\nX-Other"}, "http.auth.header must be the name of the header that carries the token (letters, "
                                                       "digits and -), and not one that means something else to a server (Host, Cookie, "
                                                       "Content-Type, ...)"),
    ({"kind": "cookie", "cookie": "a=b; c"}, "http.auth.cookie must be the name of the cookie that carries the token (letters, digits, _ . and -)"),
    ({"kind": "bearer", "header": "X-Key"}, 'http.auth.header is not for kind = "bearer"'),
    ({"kind": "exchange", "request": ["POST", "/login"], "body": {"t": "{token}"}}, 'http.auth.token_path is required for kind = "exchange"'),
    ({"kind": "exchange", "request": ["POST", "/login"], "body": {"team": "x"}, "token_path": "$.t"},
     "http.auth.body must be a table with {token} in one of its values: where the token goes in the sign-in request"),
    ({"kind": "exchange", "request": ["POST", "/login"], "body": {"t": "{token}"}, "token_path": "$.t", "scheme": "Basic"},
     "http.auth.scheme must be Bearer or Token: how the session token is sent in the Authorization header"),
    ({"kind": "exchange", "request": ["GET", "/login"], "body": {"t": "{token}"}, "token_path": "$.t"},
     "http.auth.request: the method must be POST"),
    ({"kind": "bearer", "link_param": "to ken"}, "http.auth.link_param must be the name of the query parameter that holds the token in "
                                                 "the platform's login link (letters, digits, _ and -)"),
    ({"kind": "cookie", "cookie": "sid", "link_param": 3}, "http.auth.link_param must be the name of the query parameter that holds the "
                                                           "token in the platform's login link (letters, digits, _ and -)"),
])
def test_the_token_goes_only_where_the_auth_table_can_say(auth, said):
    """No header of the table's choosing but the one that carries the token, and none that
    means something else to a server."""
    assert refused(table(auth=auth)) == said


def test_the_plan_says_every_request_and_where_the_token_goes():
    assert plan(parse_config(RCTF)) == [
        "the rctf preset's routes, with the [http] table's own keys on top",
        "link      the token variable may hold your login link (its ?token= is taken) or the token as the link writes it (%2B is read "
        "as +)",
        "sign in   POST /api/v1/auth/login: your token in the request's body; the answer's $.data.authToken is the session token",
        "list      GET /api/v1/challs, with the session token (Authorization: Bearer)",
        "files     each address at $.files[*].url: on the event's own address without your token; on another host over https only, "
        "and never with a token",
        "submit    POST /api/v1/challs/{ref}/submit, with the session token (Authorization: Bearer): the flag in the request's body, sent once",
        "solved    GET /api/v1/users/me, with the session token (Authorization: Bearer)",
    ]
    own = plan(parse_config({**table(auth={"kind": "header", "header": "X-Api-Key"}, submit=None,
                                     detail={"request": ["GET", "/api/{game}/tasks/{ref}"], "file_urls": "$.files[*]"}),
                             "game": "g7", "files_auth": True}))
    assert own == [
        "{game} is g7",
        "list      GET /api/tasks, with your token (the X-Api-Key header)",
        "detail    GET /api/{game}/tasks/{ref}, with your token (the X-Api-Key header): once for each new challenge",
        "files     each address at $.files[*]: on the event's own address with your token; on another host over https only, and "
        "never with a token",
        "submit    no route: flightdeck sends no flag (the submit policy must be manual or off)",
        "solved    GET /api/solved, with your token (the X-Api-Key header)",
    ]


def test_the_engine_is_a_caller_as_the_board_writer_and_the_link_take_one():
    made = HttpCaller(parse_config(RCTF), "https://ctf.example.test", TEAM_TOKEN)
    promised = [name for name in dir(PlatformCaller) if not name.startswith("_")] + list(PlatformCaller.__annotations__)
    assert sorted(promised) == ["label", "pull", "pull_command", "solved", "source", "submit", "token", "url"]
    assert all(hasattr(made, name) for name in promised)
    assert (made.url, made.token) == ("https://ctf.example.test", TEAM_TOKEN)
    assert (made.label, made.pull_command, made.source) == ("the http adapter", "flightdeck http pull", "http")


@pytest.mark.parametrize("kind, token", [("bearer", "two words"), ("header", "line\nbreak"), ("cookie", "a;b"), ("bearer", "")])
def test_a_token_no_header_can_carry_is_refused_and_never_shown(kind, token):
    auth = {"kind": kind, **({"header": "X-Key"} if kind == "header" else {}), **({"cookie": "sid"} if kind == "cookie" else {})}
    with pytest.raises(ValueError) as caught:
        HttpCaller(parse_config(table(auth=auth)), "https://ctf.example.test", token)
    assert "event.token_env" in str(caught.value) and (not token or token not in str(caught.value))


# ---------------------------------------------------------------------- a token handed out in a link

LINKED = quote(TEAM_TOKEN, safe="")  # the team token as rCTF's login link writes it


@pytest.mark.parametrize("held", ["the token", "the token as the link writes it", "the link", "the link with more in it"])
def test_rctfs_team_token_is_taken_from_the_login_link_or_as_the_link_writes_it(held):
    """rCTF's token is base64 (+ / =) and its login link percent-encodes it: a player who
    copies the link, or the token out of the link, must sign in as one who has the token."""
    assert all(escape in LINKED for escape in ("%2B", "%2F", "%3D"))  # the fake's token is one the link changes
    with FakeRCTF(sample()) as fake:
        value = {"the token": TEAM_TOKEN, "the token as the link writes it": LINKED, "the link": login_link(fake.url),
                 "the link with more in it": f"{fake.url}/login?next=%2Fchalls&token={LINKED}&x=1#top"}[held]
        made = HttpCaller(parse_config(RCTF), fake.url, value)
        assert made.token == TEAM_TOKEN
        assert run(made.solved()) == {"done-a4d0"}
        assert [r.json for r in fake.of("login")] == [{"teamToken": TEAM_TOKEN}]
        assert all(LINKED not in r.path and LINKED not in r.body.decode() for r in fake.requests)


def test_the_token_as_the_link_writes_it_is_cut_out_of_what_the_platform_says():
    with FakeRCTF(sample()) as fake:
        fake.script("me", answer(403, "badPerms", f"Sign in again: {login_link('https://ctf.example.test')} (token {TEAM_TOKEN})"))
        said = str(failure(HttpCaller(parse_config(RCTF), fake.url, login_link(fake.url)).solved()))
    assert "login?token=<token> (token <token>)" in said and LINKED not in said and TEAM_TOKEN not in said


@pytest.mark.parametrize("value, said", [
    ("https://ctf.example.test/login", "holds a link with no token parameter in it: put your login link in it, or the token alone"),
    ("https://ctf.example.test/login?token=", "holds a link with no token parameter in it: put your login link in it, or the token alone"),
    ("https://ctf.example.test/login?team=" + LINKED, "holds a link with no token parameter in it: put your login link in it, or the "
                                                     "token alone"),
    ("https://other.example.test/login?token=" + LINKED, "holds a link to another site (https://other.example.test, and event.url is "
                                                         "https://ctf.example.test): flightdeck does not send one site's token to "
                                                         "another. Put this event's login link in it, or the token alone"),
    ("https://[not-a-host/login?token=" + LINKED, "holds a link flightdeck cannot read: put your login link in it, or the token alone"),
    ("fake%FFtoken", "holds a %XX that stands for no character: put your login link in it, or the token alone"),
    ("https://ctf.example.test/login?token=fake%FFtoken", "holds a %XX that stands for no character: put your login link in it, or the "
                                                          "token alone"),
])
def test_a_link_that_gives_no_token_for_this_event_is_refused_and_never_shown(value, said):
    """A link to another site is another event's token: it stays home. No message shows the
    variable's value, only the two sites' addresses."""
    with pytest.raises(ValueError) as caught:
        HttpCaller(parse_config(RCTF), "https://ctf.example.test", value)
    assert str(caught.value) == f"the variable event.token_env names {said}"
    assert LINKED not in str(caught.value) and "fake%FF" not in str(caught.value)


def test_the_links_site_is_told_by_its_host_whatever_its_scheme_port_or_case():
    made = HttpCaller(parse_config(RCTF), "https://ctf.example.test", "http://CTF.Example.Test:8443/login?token=" + LINKED)
    assert made.token == TEAM_TOKEN


def test_only_a_table_that_says_so_reads_its_token_out_of_a_link():
    """link_param is the table's: without it a % in a token is the token's own, and a table
    for another platform names its own parameter."""
    with FakeSite(lambda request: Reply(200, {"ids": []})) as fake:
        run(caller(fake, token="abc%2Bdef").solved())
        run(caller(fake, table(auth={"kind": "bearer", "link_param": "key"}), token="abc%2Bdef").solved())
        run(caller(fake, table(auth={"kind": "bearer", "link_param": "key"}), token=f"{fake.url}/join?key=abc%2Fdef").solved())
        run(caller(fake, table(auth={"kind": "bearer", "link_param": "key"}), token=f"{fake.url}/join?key=a+b%3D").solved())  # + is no space
        assert [r.headers["authorization"] for r in fake.requests] == ["Bearer abc%2Bdef", "Bearer abc+def", "Bearer abc/def", "Bearer a+b="]
    assert parse_config(table()).auth.link_param is None and parse_config(RCTF).auth.link_param == "token"
    assert "link      " not in "\n".join(plan(parse_config(table())))
    assert plan(parse_config(table(auth={"kind": "bearer", "link_param": "key"})))[0] == (
        "link      the token variable may hold your login link (its ?key= is taken) or the token as the link writes it (%2B is read as +)")


# ---------------------------------------------------------------------- rCTF: the pull


def test_a_pull_signs_in_once_lists_with_the_session_and_fetches_a_file_without_it(tmp_path):
    """The login carries the team token in its body and nowhere else; the list carries the
    session token; rCTF's default upload path (/uploads?key=...) is fetched from the event's
    own address with no token at all (files_auth is false in the preset)."""
    with FakeRCTF(sample()) as fake:
        reply = run(rctf(fake).pull(tmp_path))
        assert fake.kinds() == ["login", "challs", "file"]
        login, challs, upload = fake.requests
        assert login.json == {"teamToken": TEAM_TOKEN} and "authorization" not in login.headers
        assert challs.headers["authorization"] == f"Bearer {AUTH_TOKEN}"
        assert "authorization" not in upload.headers and "cookie" not in upload.headers
        assert all(TEAM_TOKEN not in r.path and TEAM_TOKEN not in json.dumps(r.headers) for r in fake.requests)
    assert reply.problems == () and reply.notes == ()
    assert reply.challenges == (
        {"ref": "warm-7f3a", "name": "Warm Up", "category": "misc", "points": 50, "solves": 0, "description": "Read the note.",
         "files": ["0000/note.txt"]},
        {"ref": "web-19c2", "name": "Web Thing", "category": "web", "points": 250, "solves": 4, "description": "A synthetic challenge.",
         "files": []},
        {"ref": "done-a4d0", "name": "Done Before", "category": "misc", "points": 150, "solves": 0,
         "description": "A synthetic challenge.", "files": []},
    )
    assert (tmp_path / "0000" / "note.txt").read_bytes() == b"a synthetic handout\n"


def test_a_challenge_on_the_board_already_gets_no_second_download(tmp_path):
    with FakeRCTF(sample()) as fake:
        reply = run(rctf(fake).pull(tmp_path, known=["warm-7f3a"]))
        assert fake.kinds() == ["login", "challs"] and list(tmp_path.iterdir()) == []
    assert [item["ref"] for item in reply.challenges] == ["warm-7f3a", "web-19c2", "done-a4d0"] and "files" not in reply.challenges[0]


def test_files_auth_sends_the_session_with_a_file_on_the_events_own_address(tmp_path):
    with FakeRCTF(sample()[:1]) as fake:
        run(rctf(fake, files_auth=True).pull(tmp_path))
        assert fake.of("file")[0].headers["authorization"] == f"Bearer {AUTH_TOKEN}"


@pytest.fixture(scope="session")
def tls_files(tmp_path_factory):
    try:
        return make_tls(tmp_path_factory.mktemp("tls"))
    except FileNotFoundError:
        pytest.skip("not run: the openssl command is not installed, and this test needs it to make a test certificate")


@pytest.fixture
def tls(tls_files, monkeypatch):
    """The test certificates, with httpx trusting their authority (SSL_CERT_FILE) in this test."""
    monkeypatch.setenv("SSL_CERT_FILE", str(tls_files.ca))
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    return tls_files


def test_a_file_on_another_host_is_fetched_over_https_with_no_token_even_when_files_auth_is_on(tmp_path, tls):
    """A storage bucket's whole URL (rCTF's other upload provider): the token and the session
    stay behind, whatever the table says of files on the event's own address."""
    with FakeSite(lambda request: Reply(200, b"kept elsewhere\n"), tls=tls) as bucket:
        task = RTask("far-01", "Far File", files={"far.bin": f"{bucket.url}/uploads/abc/far.bin"})
        with FakeRCTF([task]) as fake:
            reply = run(rctf(fake, files_auth=True).pull(tmp_path))
        assert reply.problems == () and reply.challenges[0]["files"] == ["0000/far.bin"]
        assert (tmp_path / "0000" / "far.bin").read_bytes() == b"kept elsewhere\n"
        (fetched,) = bucket.requests
        assert "authorization" not in fetched.headers and "cookie" not in fetched.headers
        assert AUTH_TOKEN not in json.dumps(fetched.headers) and TEAM_TOKEN not in json.dumps(fetched.headers)


def test_a_redirect_of_a_file_to_another_host_is_followed_over_https_and_leaves_the_token_behind(tmp_path, tls):
    with FakeSite(lambda request: Reply(200, b"signed and served\n"), tls=tls) as bucket, FakeRCTF(sample()[:1]) as fake:
        fake.script("file", Reply(302, None, {"Location": f"{bucket.url}/bucket/note.txt?sig=synthetic", "Set-Cookie": "sid=synthetic"}))
        reply = run(rctf(fake, files_auth=True).pull(tmp_path))
        assert fake.of("file")[0].headers["authorization"] == f"Bearer {AUTH_TOKEN}"  # files_auth: on the event's own address
        (fetched,) = bucket.requests
        assert "authorization" not in fetched.headers and "cookie" not in fetched.headers
    assert reply.problems == () and (tmp_path / "0000" / "note.txt").read_bytes() == b"signed and served\n"


def test_a_file_on_another_host_over_http_is_not_fetched_and_its_challenge_is_left_out_by_name(tmp_path):
    with FakeSite(lambda request: Reply(200, b"plain\n")) as elsewhere:
        tasks = [RTask("far-01", "Far File", files={"far.bin": f"{elsewhere.url}/uploads/far.bin?sig=s3cr3t"}), *sample()[1:2]]
        with FakeRCTF(tasks) as fake:
            reply = run(rctf(fake).pull(tmp_path))
        assert elsewhere.requests == []
    assert [item["ref"] for item in reply.challenges] == ["web-19c2"]  # the others land
    assert reply.problems == (f'Far File: its file "far.bin" is on another host ({elsewhere.url}) over http; flightdeck fetches a file '
                              "from another host only over https: fetch it by hand",)
    assert "s3cr3t" not in reply.problems[0]


@pytest.mark.parametrize("status, said", [(404, "HTTP 404 (Not Found)"), (500, "HTTP 500 (Internal Server Error)")])
def test_a_file_the_platform_does_not_serve_leaves_its_challenge_out_and_no_partial_file(tmp_path, status, said):
    with FakeRCTF(sample()[:2]) as fake:
        fake.script("file", Reply(status, "no"))
        reply = run(rctf(fake).pull(tmp_path))
        assert reply.problems == (f'Warm Up: its file "note.txt" could not be fetched: {said} from {fake.url}',)
    assert [item["ref"] for item in reply.challenges] == ["web-19c2"] and not (tmp_path / "0000" / "note.txt").exists()


def test_a_file_bigger_than_flightdeck_takes_is_not_kept(tmp_path):
    with FakeRCTF(sample()[:1]) as fake:
        reply = run(HttpCaller(parse_config(RCTF), fake.url, TEAM_TOKEN, max_file_bytes=8).pull(tmp_path))
    assert reply.challenges == () and "is over 8 bytes" in reply.problems[0] and not (tmp_path / "0000" / "note.txt").exists()


@pytest.mark.parametrize("name", ["../evil.txt", "a/b.txt", "..", "", "nul\x00.txt", "x" * 300])
def test_a_file_name_that_is_not_a_plain_name_is_never_written(tmp_path, name):
    with FakeRCTF([RTask("odd-01", "Odd Name", files={name: b"x"}), *sample()[1:2]]) as fake:
        reply = run(rctf(fake).pull(tmp_path / "files"))
    assert reply.problems == ("Odd Name: one of its files has a name that is not a plain file name (a path, hidden characters, or none at all)",)
    assert [item["ref"] for item in reply.challenges] == ["web-19c2"]
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_a_challenge_the_list_gives_no_name_or_ref_for_is_left_out_and_named_and_the_others_land(tmp_path):
    def site(request):
        return Reply(200, {"tasks": [{"id": 1, "title": "One"}, {"id": 2}, {"title": "No Id"}, {"id": 4, "title": ["a", "list"]},
                                     {"id": {"deep": 1}, "title": "Odd Id"}, {"id": 6, "title": "Six", "points": "many"}]})

    with FakeSite(site) as fake:
        reply = run(caller(fake, table(**{"list.points": "$.points"})).pull(tmp_path))
    assert reply.challenges == ({"ref": "1", "name": "One", "files": []},)
    assert reply.problems == (
        "2: list.name ($.title) matched nothing",
        "No Id: list.ref ($.id) matched nothing",
        "4: list.name ($.title) matched a list of 2, not a string",
        "Odd Id: list.ref ($.id) matched an object (deep), not a string or a whole number",
        "Six: list.points ($.points) matched a string, not a number",
    )


def test_file_names_and_file_urls_must_match_the_same_number_of_values(tmp_path):
    def site(request):
        return Reply(200, {"tasks": [{"id": 1, "title": "Uneven", "files": [{"url": "/f/a", "name": "a"}, {"url": "/f/b"}]}]})

    config = table(**{"list.file_urls": "$.files[*].url", "list.file_names": "$.files[*].name"})
    with FakeSite(site) as fake:
        reply = run(caller(fake, config).pull(tmp_path))
        assert len(fake.requests) == 1  # nothing was fetched
    assert reply.challenges == () and reply.problems == (
        "Uneven: list.file_names matched 1 values and list.file_urls 2: each file needs one of each",)


def test_an_answer_that_is_not_shaped_as_the_table_says_fails_the_pull_and_an_empty_list_does_not(tmp_path):
    answers = iter([Reply(200, {"tasks": []}), Reply(200, {"challenges": [{"id": 1, "title": "Elsewhere"}]})])
    with FakeSite(lambda request: next(answers)) as fake:
        assert run(caller(fake).pull(tmp_path)).challenges == ()
        error = failure(caller(fake).pull(tmp_path))
    assert str(error) == ("GET /api/tasks answered, but list.items ($.tasks[*]) does not fit its answer: $.tasks is not in the answer. "
                          "`flightdeck http check EVENT.toml` shows what each path matches")


def test_more_challenges_than_one_pull_takes_is_no_pull(tmp_path):
    with FakeSite(lambda request: Reply(200, {"tasks": [{"id": n, "title": f"T{n}"} for n in range(1001)]})) as fake:
        error = failure(caller(fake).pull(tmp_path))
    assert str(error) == "the platform lists 1,001 challenges, more than the 1,000 flightdeck takes from one pull: nothing was added"


def test_a_detail_route_is_asked_once_for_each_new_challenge_and_its_fields_win(tmp_path):
    def site(request):
        if request.route == "/api/tasks":
            return Reply(200, {"tasks": [{"id": 7, "title": "Seven", "points": 1}, {"id": 8, "title": "Eight", "points": 2}]})
        number = request.route.rsplit("/", 1)[-1]
        return Reply(200, {"task": {"text": f"the text of {number}", "points": 500, "files": []}})

    config = {**table(**{"list.points": "$.points"}),
              "detail": {"request": ["GET", "/api/tasks/{ref}"], "description": "$.task.text", "points": "$.task.points"}}
    with FakeSite(site) as fake:
        reply = run(caller(fake, config).pull(tmp_path, known=["7"]))
        assert [r.route for r in fake.requests] == ["/api/tasks", "/api/tasks/8"]  # none for the one on the board
    assert reply.challenges == ({"ref": "7", "name": "Seven", "points": 1},
                                {"ref": "8", "name": "Eight", "points": 500, "description": "the text of 8", "files": []})


@pytest.mark.parametrize("detail_urls, saved", [
    (["/f/one.bin", "/f/two.bin", "/f/three.bin"], ["one.bin", "two.bin", "three.bin"]),  # more than the list's 2 names
    (["/f/two.bin"], ["two.bin"]),  # fewer: never saved under another file's name
])
def test_file_urls_from_the_detail_route_are_not_named_by_the_lists_file_names(tmp_path, detail_urls, saved):
    """The list's names are of the list's files: when the detail gives the addresses and no
    names, each file is named from its own address."""
    def site(request):
        if request.route == "/api/tasks":
            return Reply(200, {"tasks": [{"id": 7, "title": "Seven", "files": [{"url": "/f/x", "name": "listed.txt"},
                                                                               {"url": "/f/y", "name": "other.txt"}]}]})
        if request.route == "/api/tasks/7":
            return Reply(200, {"urls": detail_urls})
        return Reply(200, b"synthetic " + request.route.encode())

    config = {**table(**{"list.file_urls": "$.files[*].url", "list.file_names": "$.files[*].name"}),
              "detail": {"request": ["GET", "/api/tasks/{ref}"], "file_urls": "$.urls[*]"}}
    with FakeSite(site) as fake:
        reply = run(caller(fake, config).pull(tmp_path))
    assert reply.problems == ()
    assert reply.challenges[0]["files"] == [f"0000/{name}" for name in saved]
    assert sorted(path.name for path in (tmp_path / "0000").iterdir()) == sorted(saved)
    assert (tmp_path / "0000" / saved[0]).read_bytes() == b"synthetic " + detail_urls[0].encode()


def test_the_platform_going_quiet_in_the_middle_of_a_pull_stops_it_and_says_how_many_were_not_read(tmp_path):
    """Each further challenge would wait as long: what was read lands, and the next pull asks again."""
    def site(request):
        if request.route == "/api/tasks":
            return Reply(200, {"tasks": [{"id": n, "title": f"T{n}"} for n in (1, 2, 3)]})
        return Reply(200, {"text": "one"}) if request.route.endswith("/1") else HANG_UP

    config = {**table(), "detail": {"request": ["GET", "/api/tasks/{ref}"], "description": "$.text"}}
    with FakeSite(site) as fake:
        reply = run(caller(fake, config).pull(tmp_path))
        assert [r.route for r in fake.requests] == ["/api/tasks", "/api/tasks/1", "/api/tasks/2"]
    assert [item["ref"] for item in reply.challenges] == ["1"]
    assert len(reply.problems) == 1 and reply.problems[0].startswith("2 challenges not read: GET /api/tasks/{ref} got no answer (")
    assert reply.problems[0].endswith("; the next pull asks again")


# ---------------------------------------------------------------------- rCTF: the submit


def test_rctf_verdicts_are_read_from_the_body_whatever_the_status(tmp_path):
    """badFlag is HTTP 400 and an already solved challenge 409: a 4xx is an answer to read."""
    with FakeRCTF(sample()) as fake:
        engine_ = rctf(fake)
        assert run(engine_.submit("warm-7f3a", "t{nope}")) == Verdict("incorrect", "That is not the flag.")
        assert run(engine_.submit("warm-7f3a", "t{warm}")) == Verdict("correct", "That is the flag.")
        assert run(engine_.submit("done-a4d0", "t{done}")) == Verdict("already_solved", "Your team solved this one already.")
        fake.limited, fake.time_left = 1, 7500
        assert run(engine_.submit("web-19c2", "t{web}")) == Verdict("rate_limited", "Too many submissions: slow down.", None, 7.5)
        assert fake.submits() == [("warm-7f3a", "t{nope}"), ("warm-7f3a", "t{warm}"), ("done-a4d0", "t{done}"), ("web-19c2", "t{web}")]
        assert fake.kinds().count("login") == 1  # one sign-in for the caller's life
        assert all(r.headers["authorization"] == f"Bearer {AUTH_TOKEN}" and r.json.keys() == {"flag"} for r in fake.of("submit"))


@pytest.mark.parametrize("setup, ref, said", [
    (lambda fake: setattr(fake, "ended", True), "warm-7f3a", 'HTTP 401, $.kind is "badEnded": The event is over.'),
    (lambda fake: None, "no-such-challenge", 'HTTP 404, $.kind is "badChallenge": No such challenge.'),
    (lambda fake: fake.script("submit", answer(400, "badSomethingNew", "A kind nobody wrote a rule for.")), "warm-7f3a",
     'HTTP 400, $.kind is "badSomethingNew": A kind nobody wrote a rule for.'),
    (lambda fake: fake.script("submit", Reply(400, {"message": "no kind at all"})), "warm-7f3a",
     "HTTP 400, nothing at $.kind: no kind at all"),
    (lambda fake: fake.script("submit", Reply(200, {"kind": ["goodFlag"]})), "warm-7f3a", "HTTP 200, nothing at $.kind"),
    (lambda fake: fake.script("submit", Reply(200, "ok", {"Content-Type": "text/plain"})), "warm-7f3a", "HTTP 200, nothing at $.kind"),
])
def test_an_answer_no_rule_matches_is_unjudged_and_never_incorrect(setup, ref, said):
    with FakeRCTF(sample()) as fake:
        setup(fake)
        assert run(rctf(fake).submit(ref, "t{warm}")) == Verdict("unjudged", said)


def test_a_flag_is_sent_once_whatever_the_platform_answers():
    """Never retried from here: a second send could spend a try."""
    with FakeRCTF(sample()) as fake:
        engine_ = rctf(fake)
        fake.script("submit", Reply(500, {"kind": "badUnknown", "message": "a server error"}), Reply(503, {"error": "busy"}), HANG_UP)
        assert run(engine_.submit("warm-7f3a", "t{warm}")).word == "unjudged"
        assert run(engine_.submit("warm-7f3a", "t{warm}")).word == "unjudged"
        hung = failure(engine_.submit("warm-7f3a", "t{warm}"))
        assert len(fake.of("submit")) == 3
    assert str(hung).startswith("POST /api/v1/challs/{ref}/submit got no answer (") and hung.timed_out  # it may have arrived


def test_a_flag_that_never_left_this_machine_is_not_said_to_have_been_sent():
    made = HttpCaller(parse_config(table()), f"http://127.0.0.1:{closed_port()}", TOKEN)
    error = failure(made.submit("7", "t{x}"))
    assert str(error).startswith("POST /api/tasks/{ref}/flag got no answer (Connect") and not error.timed_out


def test_a_sign_in_that_fails_sends_no_flag():
    with FakeRCTF(sample()) as fake:
        error = failure(HttpCaller(parse_config(RCTF), fake.url, "not-the-team-token").submit("warm-7f3a", "t{warm}"))
        assert fake.kinds() == ["login"] and not error.timed_out
    assert str(error) == ("could not sign in: POST /api/v1/auth/login was answered with HTTP 401 (Unauthorized): The token is not one "
                          "of ours. (is the token the right one for this event?)")
    assert "not-the-team-token" not in str(error)


def test_a_challenges_ref_is_one_path_segment_whatever_it_holds():
    """Placement decides encoding: a ref cannot climb out of its place in the route."""
    with FakeRCTF(sample()) as fake:
        verdict = run(rctf(fake).submit("../../users/me?x=#", "t{warm}"))
        (sent,) = fake.of("submit") or [None]
        assert sent is not None and sent.path == "/api/v1/challs/..%2F..%2Fusers%2Fme%3Fx%3D%23/submit"
    assert verdict.word == "unjudged"


@pytest.mark.parametrize("ref", [".", ".."])
def test_a_ref_of_a_dot_or_two_is_never_sent_as_another_route(tmp_path, ref):
    """httpx folds "/a/../b" into "/b", whatever is percent-encoded around it: the flag and
    the token would go to a route the table never named."""
    def site(request):
        if request.route == "/api/tasks":
            return Reply(200, {"tasks": [{"id": ref, "title": "Dots"}]})
        return Reply(200, {"status": "ok"})

    config = {**table(), "detail": {"request": ["GET", "/api/tasks/{ref}"], "description": "$.text"}}
    with FakeSite(site) as fake:
        error = failure(caller(fake, config).submit(ref, "t{x}"))
        assert fake.requests == [] and not error.timed_out
        reply = run(caller(fake, config).pull(tmp_path))
        assert [r.route for r in fake.requests] == ["/api/tasks"]  # no detail asked for
    assert str(error) == f"POST /api/tasks/{{ref}}/flag: {{ref}} is {ref}, which would name another route, so flightdeck did not send it"
    assert reply.challenges == () and reply.problems == (
        f"Dots: GET /api/tasks/{{ref}}: {{ref}} is {ref}, which would name another route, so flightdeck did not send it",)


def test_a_web_page_in_answer_to_the_flag_says_the_flag_may_have_arrived():
    """A proxy's page (a 524, a block page) can stand in front of a platform that took the
    flag: timed_out is what makes the run's link warn that it may have arrived."""
    with FakeSite(lambda request: Reply(524, "<!doctype html><html>A timeout occurred</html>", {"Content-Type": "text/html"})) as fake:
        error = failure(caller(fake).submit("7", "t{x}"))
        assert len(fake.requests) == 1
    assert error.timed_out and str(error).startswith("the flag was sent, and then: POST /api/tasks/{ref}/flag was answered with a web page")


def test_a_web_page_where_an_answer_should_be_is_a_stop_for_a_human_never_a_verdict(tmp_path):
    page = Reply(200, "<!doctype html><html><body>Checking your browser...</body></html>")
    config = table(**{"submit.status": {"200": "correct", "403": "incorrect"}})
    with FakeSite(lambda request: page) as fake:
        engine_ = caller(fake, config)
        for call in (engine_.pull(tmp_path), engine_.solved(), engine_.submit("7", "t{x}")):
            error = failure(call)
            assert "was answered with a web page for a person, not an API answer (not JSON, HTTP 200 (OK))" in str(error)
            assert "flightdeck does not try to pass such a page" in str(error)
        fake.handler = lambda request: Reply(403, "<html>Forbidden: log in</html>")
        assert "a web page for a person" in str(failure(engine_.submit("7", "t{x}")))  # not the 403 rule's "incorrect"


def test_a_status_rule_judges_an_answer_with_no_value_and_takes_retry_after_from_the_header():
    replies = iter([Reply(204, None), Reply(429, {"error": "slow"}, {"Retry-After": "12"}), Reply(418, None),
                    Reply(403, {"status": "bad"})])
    config = table(**{"submit.status": {"204": "correct", "429": "rate_limited", "403": "unjudged"}})
    with FakeSite(lambda request: next(replies)) as fake:
        engine_ = caller(fake, config)
        assert run(engine_.submit("7", "t{x}")) == Verdict("correct", "")
        assert run(engine_.submit("7", "t{x}")) == Verdict("rate_limited", "", None, 12.0)
        assert run(engine_.submit("7", "t{x}")) == Verdict("unjudged", "HTTP 418, nothing at $.status")
        assert run(engine_.submit("7", "t{x}")) == Verdict("incorrect", "")  # the value's rule comes before the status's


def test_the_tries_left_and_the_platforms_words_are_read_by_their_paths():
    config = table(**{"submit.tries_left_path": "$.left", "submit.detail_path": "$.why",
                      "submit.verdicts": {"bad": "incorrect", "true": "correct"}})
    replies = iter([Reply(200, {"status": "bad", "left": 2, "why": "Nope.\x1b[31m red"}), Reply(200, {"status": "bad", "left": -1}),
                    Reply(200, {"status": True, "left": "many"})])
    with FakeSite(lambda request: next(replies)) as fake:
        engine_ = caller(fake, config)
        first = run(engine_.submit("7", "t{x}"))
        assert first.word == "incorrect" and first.tries_left == 2 and "\x1b" not in first.detail and first.detail.startswith("Nope.")
        assert run(engine_.submit("7", "t{x}")) == Verdict("incorrect", "", None)  # a count that is not one is no count
        assert run(engine_.submit("7", "t{x}")) == Verdict("correct", "", None)  # true and false are the keys "true" and "false"


def test_a_ref_sent_as_a_number_is_a_json_number_and_one_that_is_not_a_number_sends_nothing():
    config = table(**{"submit.request": ["POST", "/api/flag"], "submit.body": {"challenge": "{ref:int}", "flag": "{flag}", "extra": {"n": 1}}})
    with FakeSite(lambda request: Reply(200, {"status": "ok"})) as fake:
        engine_ = caller(fake, config)
        assert run(engine_.submit("17", 't{"quoted" \\ flag}')).word == "correct"
        assert fake.requests[0].json == {"challenge": 17, "flag": 't{"quoted" \\ flag}', "extra": {"n": 1}}
        error = failure(engine_.submit("warm-up", "t{x}"))
        assert len(fake.requests) == 1 and not error.timed_out
    assert str(error) == "the table sends the challenge's ref as a number ({ref:int}), and this challenge's ref is not one"


def test_a_table_with_no_submit_route_sends_nothing():
    with FakeSite(lambda request: Reply(200, {})) as fake:
        error = failure(caller(fake, table(submit=None)).submit("7", "t{x}"))
        assert fake.requests == []
    assert str(error) == "the [http] table has no [http.submit], so flightdeck has no route to send a flag by"


# ---------------------------------------------------------------------- a submission judged later


POLL = {"request": ["GET", "/api/game/{game}/status/{submission}"], "id_path": "$", "pending": ["FlagSubmitted"], "every": 0.5,
        "at_most": 4, "verdict_path": "$"}


def as_json(value: object) -> Reply:
    """An answer whose whole body is one JSON value (a bare string or number, as some platforms answer)."""
    return Reply(200, json.dumps(value).encode(), {"Content-Type": "application/json"})


def polled(states: list, **poll) -> tuple[dict, callable]:
    """A table whose submit answers with a submission's number and whose status route answers
    `states` in turn (the last repeated), and the handler that serves them."""
    left = list(states)

    def site(request):
        if request.method == "POST":
            return as_json(4242)
        return as_json(left.pop(0) if len(left) > 1 else left[0])

    config = {**table(**{"submit.request": ["POST", "/api/game/{game}/challenges/{ref}"],
                         "submit.verdicts": {"Accepted": "correct", "WrongAnswer": "incorrect"},
                         "submit.poll": {**POLL, **poll}}), "game": "12"}
    return config, site


def test_a_submission_the_platform_judges_later_is_looked_at_until_it_is_judged():
    config, site = polled(["FlagSubmitted", "FlagSubmitted", "Accepted"])
    with FakeSite(site) as fake:
        engine_, waits = caller(fake, config), []

        async def nap(seconds):
            waits.append(seconds)

        engine_.sleep = nap
        assert run(engine_.submit("9", "t{x}")).word == "correct"
        assert [(r.method, r.path) for r in fake.requests] == [("POST", "/api/game/12/challenges/9")] + [("GET", "/api/game/12/status/4242")] * 3
    assert waits == [0.5, 0.5]  # between the looks, never before the first


def test_a_submission_still_pending_after_the_last_look_is_no_verdict_and_may_have_been_accepted():
    config, site = polled(["FlagSubmitted"])
    with FakeSite(site) as fake:
        engine_ = caller(fake, config)
        engine_.sleep = lambda seconds: asyncio.sleep(0)
        error = failure(engine_.submit("9", "t{x}"))
        assert len(fake.requests) == 1 + 4  # one send, at_most looks
    assert error.timed_out and str(error) == ('the flag was sent, and the platform had not judged it after 4 looks, 0.5 s apart '
                                              '($ is "FlagSubmitted")')


def test_a_look_the_rules_do_not_know_is_unjudged_and_a_look_that_fails_says_the_flag_was_sent():
    config, site = polled(["FlagSubmitted", "CheatDetected"])
    with FakeSite(site) as fake:
        engine_ = caller(fake, config)
        engine_.sleep = lambda seconds: asyncio.sleep(0)
        assert run(engine_.submit("9", "t{x}")) == Verdict("unjudged", 'HTTP 200, $ is "CheatDetected"')
        fake.handler = lambda request: as_json(4242) if request.method == "POST" else HANG_UP
        error = failure(engine_.submit("9", "t{x}"))
    assert error.timed_out and str(error).startswith("the flag was sent, and then: GET /api/game/{game}/status/{submission} got no answer")


def test_a_submit_answer_that_is_a_verdict_already_is_not_looked_at_again():
    config, site = polled(["Accepted"])
    with FakeSite(lambda request: as_json("WrongAnswer")) as fake:
        assert run(caller(fake, {**config, "submit": {**config["submit"], "verdict_path": "$"}}).submit("9", "t{x}")).word == "incorrect"
        assert len(fake.requests) == 1


# ---------------------------------------------------------------------- the solved list, auth, and what is shown


def test_the_solved_list_is_the_refs_at_its_path_and_the_team_token_it_echoes_is_cut_out():
    with FakeRCTF(sample()) as fake:
        engine_ = rctf(fake)
        assert run(engine_.solved()) == {"done-a4d0"}
        assert fake.of("me")[0].headers["authorization"] == f"Bearer {AUTH_TOKEN}"
        fake.script("me", answer(200, "goodUserData", "The team.", {"solves": [], "teamToken": TEAM_TOKEN}))
        assert run(engine_.solved()) == set()
        fake.script("me", answer(200, "goodUserData", "The team.", {"teamToken": TEAM_TOKEN}),
                    answer(200, "goodUserData", "The team.", {"solves": [{"id": ["not", "a", "ref"]}]}),
                    answer(401, "badToken", f"The token {AUTH_TOKEN} (for team token {TEAM_TOKEN}) is not valid.\x1b[2J"))
        assert str(failure(engine_.solved())) == ("GET /api/v1/users/me answered, but solved.refs ($.data.solves[*].id) does not fit "
                                                  "its answer: $.data.solves is not in the answer")
        assert str(failure(engine_.solved())) == ("GET /api/v1/users/me answered, but solved.refs ($.data.solves[*].id) matched a "
                                                  "value that is not a challenge's ref (a string or a whole number)")
        said = str(failure(engine_.solved()))
    assert said.startswith("GET /api/v1/users/me was answered with HTTP 401 (Unauthorized): The token <token> (for team token <token>)")
    assert TEAM_TOKEN not in said and AUTH_TOKEN not in said and "\x1b" not in said


@pytest.mark.parametrize("auth, header, value", [
    ({"kind": "bearer"}, "authorization", f"Bearer {TOKEN}"),
    ({"kind": "token"}, "authorization", f"Token {TOKEN}"),
    ({"kind": "header", "header": "X-Api-Key"}, "x-api-key", TOKEN),
    ({"kind": "cookie", "cookie": "session"}, "cookie", f"session={TOKEN}"),
])
def test_each_kind_of_auth_sends_the_token_in_its_one_place(auth, header, value):
    with FakeSite(lambda request: Reply(200, {"ids": [3, "x-9"]})) as fake:
        assert run(caller(fake, table(auth=auth)).solved()) == {"3", "x-9"}
        (sent,) = fake.requests
    assert sent.headers[header] == value and TOKEN not in sent.path
    assert [name for name, text in sent.headers.items() if TOKEN in text] == [header]  # nowhere else


def test_an_api_request_never_follows_a_redirect_with_the_token():
    """A redirect is an answer flightdeck refuses, not a new place to send the token."""
    with FakeSite(lambda request: Reply(200, {"ids": []})) as elsewhere:
        with FakeSite(lambda request: Reply(302, None, {"Location": f"{elsewhere.url}/api/solved"})) as fake:
            error = failure(caller(fake).solved())
        assert elsewhere.requests == []
    assert str(error) == ("GET /api/solved was answered with a redirect (HTTP 302), which flightdeck does not follow with your token: is "
                          "event.url the platform's own address?")


def test_a_session_the_platform_refuses_is_asked_for_again_but_not_more_often_than_the_wait(monkeypatch):
    with FakeRCTF(sample()) as fake:
        engine_ = rctf(fake)
        run(engine_.solved())
        fake.script("me", answer(401, "badToken", "expired"), answer(401, "badToken", "expired"))
        failure(engine_.solved())  # refused: within the wait the session is kept
        assert fake.kinds().count("login") == 1
        monkeypatch.setattr(engine, "RELOGIN_SECONDS", 0.0)
        failure(engine_.solved())  # refused again: now the session is forgotten
        assert run(engine_.solved()) == {"done-a4d0"} and fake.kinds().count("login") == 2


def test_a_sign_in_whose_answer_holds_no_session_token_is_a_failure_by_name():
    with FakeRCTF(sample()) as fake:
        fake.script("login", answer(200, "goodLogin", "Signed in.", {"token": "elsewhere"}),
                    answer(200, "goodLogin", "Signed in.", {"authToken": "two words"}))
        for _ in range(2):
            assert str(failure(rctf(fake).solved())) == ("could not sign in: POST /api/v1/auth/login answered, but auth.token_path "
                                                         "($.data.authToken) matched no session token in its answer")
        assert fake.kinds() == ["login", "login"]


def test_an_answer_that_comes_a_byte_at_a_time_does_not_outlast_the_deadline(tmp_path):
    """Each byte arrives in time for the transport, so only a deadline for the whole answer ends it."""
    slow = Reply(200, {"ids": ["x" * 400]}, drip=0.02)
    with FakeSite(lambda request: slow) as fake:
        error = failure(caller(fake, deadline=0.3).solved())
        sent = failure(caller(fake, deadline=0.3).submit("7", "t{x}"))
    assert str(error) == "GET /api/solved got no answer (no whole answer within 0.3 s)" and not error.timed_out
    assert sent.timed_out  # the flag left: it may have arrived
    with FakeSite(lambda request: Reply(200, {"tasks": [{"id": 1, "title": "Slow File", "f": "/f/big.bin"}]})
                  if request.route == "/api/tasks" else Reply(200, b"x" * 400, drip=0.02)) as fake:
        reply = run(caller(fake, table(**{"list.file_urls": "$.f"}), file_seconds=0.3).pull(tmp_path))
    assert reply.challenges == () and reply.problems == ('Slow File: its file "big.bin" was not all here within 0.3 s: fetch it by hand',)
    assert not (tmp_path / "0000" / "big.bin").exists()


def test_an_answer_bigger_than_its_limit_is_refused():
    with FakeSite(lambda request: Reply(200, {"ids": ["x" * 100] * 11_000})) as fake:  # a little over a megabyte
        error = failure(caller(fake).solved())
    assert str(error) == "GET /api/solved was answered with more than 1,000,000 bytes"


def test_the_game_placeholder_is_filled_from_the_table_in_every_route():
    config = {**table(**{"list.request": ["GET", "/api/game/{game}/tasks"], "solved.request": ["GET", "/api/game/{game}/solved"]}),
              "game": "summer 26/b"}
    with FakeSite(lambda request: Reply(200, {"ids": [], "tasks": []})) as fake:
        engine_ = caller(fake, config)
        run(engine_.solved())
        run(engine_.pull(Path("unused")))
        assert [r.path for r in fake.requests] == ["/api/game/summer%2026%2Fb/solved", "/api/game/summer%2026%2Fb/tasks"]


def test_an_address_with_a_path_keeps_its_routes_under_that_path():
    with FakeSite(lambda request: Reply(200, {"ids": []})) as fake:
        run(HttpCaller(parse_config(table()), fake.url + "/ctf/", TOKEN).solved())
        assert fake.requests[0].path == "/ctf/api/solved"


# ---------------------------------------------------------------------- the dry run


def row(name: str, path: str, said: str) -> str:
    """One field's line in the dry run: its name, its path, what it matched."""
    return f"    {name:<13}{path:<26} {said}"


def test_the_dry_run_shows_what_each_path_matched_and_submits_and_downloads_nothing():
    with FakeRCTF(sample()) as fake:
        found = run(rctf(fake).check(show=1))
        assert fake.kinds() == ["login", "challs", "me"]  # no file, no submit
    assert found.problems == 0
    assert found.lines == [
        f"sign in  POST /api/v1/auth/login: $.data.authToken matched a session token ({len(AUTH_TOKEN)} characters)",
        "list     GET /api/v1/challs: HTTP 200, $.data[*] matched 3 challenges",
        "  challenge 1",
        row("ref", "$.id", '"warm-7f3a"'),
        row("name", "$.name", '"Warm Up"'),
        row("category", "$.category", '"misc"'),
        row("points", "$.points", "50"),
        row("solves", "$.solves", "0"),
        row("description", "$.description", '"Read the note."'),
        row("file_urls", "$.files[*].url", '1 value: "/uploads?key=warm-7f3a-note.txt"'),
        row("file_names", "$.files[*].name", '1 value: "note.txt"'),
        "  the other 2: each has a ref and a name",
        "solved   GET /api/v1/users/me: HTTP 200, $.data.solves[*].id matched 1 ref, 1 of them on the list",
    ]
    assert AUTH_TOKEN not in "\n".join(found.lines) and TEAM_TOKEN not in "\n".join(found.lines)


def test_the_dry_run_counts_a_path_that_matches_nothing_and_solved_refs_that_are_not_on_the_list():
    def site(request):
        if request.route == "/api/tasks":
            return Reply(200, {"tasks": [{"id": 1, "name": "The Title Is Under Another Key", "points": [1, 2]}, {"id": 2}]})
        return Reply(200, {"ids": ["slug-one"]})

    with FakeSite(site) as fake:
        found = run(caller(fake, table(**{"list.points": "$.points[*]", "list.category": "$.category"})).check(show=1))
    assert found.problems == 4
    assert found.lines == [
        "list     GET /api/tasks: HTTP 200, $.tasks[*] matched 2 challenges",
        "  challenge 1",
        row("ref", "$.id", "1"),
        row("name", "$.title", "matched nothing: REQUIRED"),
        row("category", "$.category", "matched nothing (left out)"),
        row("points", "$.points[*]", "matched 2 values, and one is wanted"),
        "  the other 1: 1 cannot be read (a pull names each, with the reason)",
        "solved   GET /api/solved: HTTP 200, $.ids[*] matched 1 ref, 0 of them on the list",
        "  none of the solved refs is a ref on the list: is solved.refs the same id as list.ref?",
    ]


def test_the_dry_run_says_when_a_path_matches_the_wrong_kind_of_value():
    with FakeSite(lambda request: Reply(200, {"tasks": [{"id": 1, "title": "One", "points": "many"}], "ids": []})) as fake:
        found = run(caller(fake, table(**{"list.points": "$.points"})).check())
    assert found.problems == 1 and found.lines[2:5] == [
        row("ref", "$.id", "1"), row("name", "$.title", '"One"'), row("points", "$.points", '"many"')]
    assert found.lines[5] == "    a pull would leave it out: list.points ($.points) matched a string, not a number"


def test_the_dry_run_shows_a_challenge_with_no_files_as_no_values_not_as_a_path_that_failed():
    with FakeRCTF(sample()[1:2]) as fake:
        found = run(rctf(fake).check())
    assert found.problems == 0
    assert row("file_urls", "$.files[*].url", "no values") in found.lines and row("file_names", "$.files[*].name", "no values") in found.lines
