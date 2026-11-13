"""B-112, the online half: the read-only bot client and the capture (ctf/discordapi.py), against a fake
API this test starts on 127.0.0.1 (tests/discord_fake.py). The token is a dummy; nothing leaves loopback.

Time is driven: the client's `sleep` and `clock` are injected, so no test waits on the wall clock.
"""
from __future__ import annotations

import json

import pytest

import discord_fake
from discord_fake import GUILD, FakeDiscord, server_routes
from ctf import discordapi as api
from ctf import discordrecon as dr

TOKEN = "not-a-real-token-b112-loopback-only"


class StepClock:
    """A clock that only moves when the client sleeps."""

    def __init__(self):
        self.now, self.slept = 100.0, []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.slept.append(s)
        self.now += s


def client_for(fake, **kw):
    kw.setdefault("min_interval", 0)
    return api.Client(fake.base, TOKEN, **kw)


def items_of(res, kind):
    return [(i.where, i.text) for i in res.items if i.kind == kind]


# ------------------------------------------------------------------------------- capture

def test_capture_reads_the_whole_server_with_gets_only():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        c = client_for(fake)
        res = api.capture(c, GUILD)
    assert {r.method for r in fake.requests} == {"GET"}
    assert all(r.headers["authorization"] == "Bot " + TOKEN for r in fake.requests)
    assert all(r.headers["user-agent"].startswith("DiscordBot (") for r in fake.requests)
    assert fake.paths()[:3] == ["/users/@me", f"/guilds/{GUILD}", f"/guilds/{GUILD}/channels"]
    assert res.requests == len(fake.requests) == c.requests and res.guild == {"id": GUILD, "name": "Recon Test Fleet"}

    assert items_of(res, "guild-description") == [("server", "The fleet's home port")]
    # the channel list is not filtered by what the bot can open: the locked channel's topic is there
    assert items_of(res, "channel-topic") == [
        ("#rules", "Read me"), ("#watch", "The watch is broadcasting. Recognition word: **halyard**"),
        ("#locked", "staff only"), ("#help", "Post guidelines")]
    assert items_of(res, "channel-name") == [("#rules", "rules"), ("#watch", "watch"), ("#locked", "locked"),
                                             ("#help", "help"), ("#Voice", "Voice")]          # by position
    assert items_of(res, "category-name") == [("category Bridge", "Bridge")]
    assert items_of(res, "forum-tag") == [("#help", "solved"), ("#help", "open")]
    assert items_of(res, "role") == [("roles", "Watch Officer"), ("roles", "Deckhand")]   # no @everyone
    assert items_of(res, "emoji") == [("emoji", "anchor"), ("emoji", "RECONwish_granted")]
    assert items_of(res, "sticker") == [("stickers", "lighthouse")]
    assert ("sticker lighthouse", "a light in the fog beacon") in items_of(res, "other")
    assert items_of(res, "thread-name") == [("thread side quest (in #watch)", "side quest")]
    assert items_of(res, "event") == [("event Kickoff", "Kickoff\nOpening call\nthe main deck")]
    assert items_of(res, "soundboard") == [("soundboard", "foghorn")]
    assert items_of(res, "onboarding") == [("onboarding", "Pick your station\nEngine room keep it running")]
    assert items_of(res, "welcome") == [("welcome screen", "Fall in with the fleet\nStart here")]
    # only the server's bots are listed, never its people
    assert items_of(res, "bot-name") == [("bot watchtower", "watchtower")]
    assert items_of(res, "bot-about") == [("bot watchtower", "I keep the watch. RECON{b0t_ab0ut_m3}")]
    assert not [i for i in res.items if "Admiral" in i.text or "Admiral" in i.where]
    assert "/applications/900/rpc" not in fake.paths()

    # messages: the rules channel's are kind `rules`, oldest first although the API answers newest first
    rules = [i for i in res.items if i.kind == "rules"]
    assert [i.seq for i in rules] == list(range(1, 11)) and rules[1].text == "Respect everyone"
    assert rules[0].author == "organizer" and {i.where for i in rules} == {"#rules"}
    assert items_of(res, "pin") == [("#watch", "pinned order of the day")]
    assert items_of(res, "message") == [("#watch", "first\nSignal\nembedded line\nk\nv\nfoot"), ("#watch", "second"),
                                        ("thread side quest (in #watch)", "thread opener")]
    first = [r for r in fake.requests if r.path == "/channels/11/messages"]
    assert [r.query for r in first] == [{"after": "0", "limit": "50"}]            # the channel start
    assert "/channels/15/messages" not in fake.paths() and "/channels/14/messages" not in fake.paths()

    # a place the bot may not open is a note, not a failure and not a silent gap
    assert "#locked: pins: not readable by the bot (HTTP 403)" in res.notes
    assert "#locked: first messages: not readable by the bot (HTTP 403)" in res.notes
    assert any("member profiles" in n and "by hand" in n for n in res.notes)
    assert res.partial is False
    assert all(i.source == "api" for i in res.items)
    assert TOKEN not in json.dumps([i.to_dict() for i in res.items]) + json.dumps(res.notes)


def test_a_captured_server_analyzes_end_to_end():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        res = api.capture(client_for(fake), GUILD)
    snap = dr.Snapshot()
    snap.add(res.items, source="api", notes=res.notes)
    rep = dr.analyze(snap, discord_fake.profile())
    got = {c.value: c for c in rep.candidates}
    assert got["RECON{A4}"].kind == "acrostic-flag"
    assert got["RECON{A4}"].how == "first character of each line of the rules of #rules spells it"
    assert got["RECON{b0t_ab0ut_m3}"].kind == "flag" and got["RECON{b0t_ab0ut_m3}"].where == "bot watchtower"
    assert got["halyard"].kind == "recognition" and got["halyard"].where == "#watch"
    assert got["RECONwish_granted"].kind == "braceless"
    assert got["RECON{example_flag_here}"].kind == "decoy-flag"
    assert rep.candidates[0].value == "RECON{A4}" and rep.candidates[-1].kind == "decoy-flag"
    assert any("#locked" in n for n in rep.notes)


def test_recent_messages_are_added_after_the_first_and_not_twice():
    routes = server_routes()
    with FakeDiscord(TOKEN, routes) as fake:
        res = api.capture(client_for(fake), GUILD, first=50, recent=20)
    watch = [r.query for r in fake.requests if r.path == "/channels/12/messages"]
    assert watch == [{"after": "0", "limit": "50"}, {"limit": "20"}]
    assert items_of(res, "message").count(("#watch", "second")) == 1        # same ids: listed once
    with FakeDiscord(TOKEN, routes) as fake:
        api.capture(client_for(fake), GUILD, first=0, recent=500, bots=0)
    assert [r.query for r in fake.requests if r.path == "/channels/12/messages"] == [{"limit": "100"}]
    assert f"/guilds/{GUILD}/members" not in fake.paths()                     # bots=0: the member list is not read


def test_the_bot_cap_lists_only_that_many_bots():
    routes = server_routes()
    routes[f"/guilds/{GUILD}/members"] = routes[f"/guilds/{GUILD}/members"] + [
        {"user": {"id": "902", "username": "lamplighter", "bot": True}}]
    routes["/applications/902/rpc"] = {"id": "902", "description": "I light the lamps"}
    with FakeDiscord(TOKEN, routes) as fake:
        res = api.capture(client_for(fake), GUILD, bots=1)
    assert items_of(res, "bot-name") == [("bot watchtower", "watchtower")]
    assert "/applications/902/rpc" not in fake.paths() and len(items_of(res, "bot-about")) == 1
    with FakeDiscord(TOKEN, routes) as fake:
        res = api.capture(client_for(fake), GUILD, bots=2)
    assert items_of(res, "bot-name") == [("bot watchtower", "watchtower"), ("bot lamplighter", "lamplighter")]
    assert "/applications/902/rpc" in fake.paths()


def test_a_user_account_token_is_refused_before_the_server_is_read():
    routes = server_routes()
    routes["/users/@me"] = {"id": "5", "username": "a-person"}
    with FakeDiscord(TOKEN, routes) as fake:
        with pytest.raises(api.DiscordRefused, match="not a bot application"):
            api.capture(client_for(fake), GUILD)
    assert fake.paths() == ["/users/@me"]


def test_a_server_the_bot_is_not_in_is_a_named_error():
    routes = server_routes()
    del routes[f"/guilds/{GUILD}"]
    with FakeDiscord(TOKEN, routes) as fake:
        with pytest.raises(api.DiscordError, match="not a member.*human step"):
            api.capture(client_for(fake), GUILD)
    with pytest.raises(api.DiscordError, match="not numeric"):
        api.capture(api.Client("http://127.0.0.1:9/api", TOKEN), "my-server")


def test_a_failed_optional_step_marks_the_capture_partial():
    routes = server_routes()
    routes[f"/guilds/{GUILD}/scheduled-events"] = (500, {"message": "boom"})
    routes[f"/guilds/{GUILD}/onboarding"] = (200, b"<html>not json</html>")
    with FakeDiscord(TOKEN, routes) as fake:
        res = api.capture(client_for(fake), GUILD)
    assert res.partial is True
    assert any(n.startswith("scheduled events: failed") and "HTTP 500" in n for n in res.notes)
    assert any(n.startswith("onboarding: failed") and "not JSON" in n for n in res.notes)
    assert items_of(res, "soundboard") == [("soundboard", "foghorn")]         # the capture went on


def test_the_request_budget_ends_the_capture_with_a_note():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        res = api.capture(client_for(fake, max_requests=6), GUILD)
    assert len(fake.requests) == 6 and res.requests == 6
    assert res.partial is True
    assert sum("request budget (6) is spent" in n for n in res.notes) == 1    # named once, then it stops
    assert items_of(res, "channel-topic") and not items_of(res, "rules")       # what came before is kept
    with FakeDiscord(TOKEN, server_routes()) as fake:
        with pytest.raises(api.BudgetSpent):
            api.capture(client_for(fake, max_requests=2), GUILD)                # the core reads must fit


def test_an_id_that_is_not_numeric_never_reaches_a_request_path():
    routes = server_routes()
    routes[f"/guilds/{GUILD}/channels"] = [
        {"id": "12/../../users/@me", "type": 0, "name": "sneaky", "position": "first"},   # not a number: 0
        {"id": "13?x=1", "type": 0, "name": "query", "position": 2}]
    routes[f"/guilds/{GUILD}/members"] = [{"user": {"id": "../../../users/@me", "username": "evil", "bot": True}}]
    with FakeDiscord(TOKEN, routes) as fake:
        res = api.capture(client_for(fake), GUILD)
    assert not [p for p in fake.paths() if "sneaky" in p or ".." in p or p.startswith("/channels/1")]
    assert not [p for p in fake.paths() if p.startswith("/applications/")]
    assert items_of(res, "channel-name") == [("#sneaky", "sneaky"), ("#query", "query")]


def test_channels_past_the_cap_are_named_not_dropped_silently():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        res = api.capture(client_for(fake), GUILD, max_channels=1)
    assert res.partial is True and any("3 channel(s) past the first 1" in n for n in res.notes)
    assert "/channels/11/messages" in fake.paths() and "/channels/12/messages" not in fake.paths()
    assert items_of(res, "channel-topic")[1][0] == "#watch"             # its topic is still captured


# ------------------------------------------------------------------------------- the client

def test_an_oversized_answer_is_refused(monkeypatch):
    monkeypatch.setattr(api, "MAX_BODY", 64)
    with FakeDiscord(TOKEN, {"/a": {"pad": "x" * 200}, "/b": {"ok": 1}}) as fake:
        c = client_for(fake)
        with pytest.raises(api.DiscordError, match="over 64 bytes"):
            c.get("/a")
        assert c.get("/b") == {"ok": 1}


def test_the_token_is_not_in_an_error_a_repr_or_the_client_dict():
    with FakeDiscord("another-token", {"/users/@me": {"bot": True}}) as fake:       # ours is rejected
        c = client_for(fake)
        with pytest.raises(api.HttpError) as e:
            c.get("/users/@me")
    assert e.value.status == 401 and "token was rejected" in str(e.value)
    assert fake.requests[0].headers["authorization"] == "Bot " + TOKEN              # it was sent
    assert TOKEN not in str(e.value) and TOKEN not in repr(c)
    assert TOKEN not in repr({k: v for k, v in vars(c).items() if k != "_token"})


def test_an_error_message_that_echoes_the_token_is_scrubbed():
    routes = {"/guilds/1": (400, {"message": f"bad header: Bot {TOKEN}", "code": 0})}
    with FakeDiscord(TOKEN, routes) as fake:
        with pytest.raises(api.HttpError) as e:
            client_for(fake).get("/guilds/1")
    assert e.value.status == 400 and "<redacted>" in str(e.value) and TOKEN not in str(e.value)


def test_a_redirect_is_refused_and_the_header_never_reaches_the_other_host():
    with FakeDiscord(TOKEN, {"/users/@me": {"bot": True}}) as other:
        routes = {"/users/@me": (302, {"message": "moved"}, {"Location": other.base + "/users/@me"})}
        with FakeDiscord(TOKEN, routes) as fake:
            with pytest.raises(api.HttpError) as e:
                client_for(fake).get("/users/@me")
        assert e.value.status == 302 and "redirect refused" in str(e.value)
        assert len(fake.requests) == 1 and other.requests == []


def test_no_proxy_is_taken_from_the_environment(monkeypatch):
    # A proxy named in the environment would see the Authorization header: the client ignores it.
    with FakeDiscord(TOKEN, {"/users/@me": {"bot": True}}) as proxy:
        for name in ("no_proxy", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.setenv(name, proxy.origin)
        with FakeDiscord(TOKEN, {"/users/@me": {"bot": True}}) as fake:
            assert client_for(fake).get("/users/@me") == {"bot": True}
        assert len(fake.requests) == 1 and proxy.requests == []


def test_a_token_with_a_line_break_or_control_character_is_refused_without_being_echoed():
    for bad in ("DUMMYAAAA\nDUMMYBBBB", "DUMMYAAAA\x00DUMMYBBBB", "DUMMYAAAA DUMMYBBBB", "DUMMYAAAA\u00e9BBBB"):
        with pytest.raises(api.DiscordRefused, match="outside printable ASCII") as e:
            api.Client("http://127.0.0.1:9/api", bad)
        assert "DUMMYAAAA" not in str(e.value) and "BBBB" not in str(e.value)
    api.Client("http://127.0.0.1:9/api", "  " + TOKEN + "\n")              # surrounding space is trimmed


def test_a_request_that_cannot_be_sent_never_quotes_the_header():
    # Belt and braces behind the token check: http.client's ValueError quotes the bad header (escaped,
    # so a plain replace of the token would miss it); its text is never passed on.
    with FakeDiscord(TOKEN, {"/users/@me": {"bot": True}}) as fake:
        c = client_for(fake)
        c._token = "DUMMYAAAA\nDUMMYBBBB"
        with pytest.raises(api.DiscordError, match="could not be sent") as e:
            c.get("/users/@me")
    assert "DUMMYAAAA" not in str(e.value) and "DUMMYBBBB" not in str(e.value)
    assert fake.requests == []


def test_a_rate_limit_is_waited_out_and_then_answered():
    sc = StepClock()
    routes = {"/guilds/1": discord_fake.Seq([(429, {"message": "slow down", "retry_after": 1.5}),
                                             (429, {"message": "slow down"}, {"Retry-After": "2"}),
                                             {"id": "1"}])}
    with FakeDiscord(TOKEN, routes) as fake:
        c = client_for(fake, sleep=sc.sleep, clock=sc.clock)
        assert c.get("/guilds/1") == {"id": "1"}
    assert sc.slept == [1.5, 2.0] and c.requests == 3 == len(fake.requests)


def test_a_rate_limit_is_not_waited_past_the_cap_or_retried_forever():
    sc = StepClock()
    with FakeDiscord(TOKEN, {"/a": (429, {"retry_after": 3600})}) as fake:
        with pytest.raises(api.HttpError, match="rate limited for 3600 s, over the 30 s"):
            client_for(fake, sleep=sc.sleep, clock=sc.clock).get("/a")
    assert sc.slept == [] and len(fake.requests) == 1
    with FakeDiscord(TOKEN, {"/a": (429, {"retry_after": 1})}) as fake:
        with pytest.raises(api.HttpError, match="still rate limited after 2 retries"):
            client_for(fake, sleep=sc.sleep, clock=sc.clock, max_retries=2).get("/a")
    assert sc.slept == [1.0, 1.0] and len(fake.requests) == 3


def test_requests_are_spaced_by_the_minimum_interval():
    sc = StepClock()
    with FakeDiscord(TOKEN, {"/a": {"ok": 1}}) as fake:
        c = client_for(fake, min_interval=0.5, sleep=sc.sleep, clock=sc.clock)
        for _ in range(4):
            c.get("/a")
        assert sc.slept == [0.5, 0.5, 0.5]                # not before the first
        sc.now += 10                                      # time passed on its own: no wait is owed
        c.get("/a")
        assert sc.slept == [0.5, 0.5, 0.5]


def test_the_client_refuses_an_unsafe_base_a_missing_token_and_a_bad_path():
    with pytest.raises(api.DiscordRefused, match="plain http to a non-loopback host"):
        api.Client("http://discord.example/api/v10", TOKEN)
    with pytest.raises(api.DiscordRefused, match="credentials"):
        api.Client("https://user:pw@discord.example/api", TOKEN)
    with pytest.raises(api.DiscordRefused, match="not an http"):
        api.Client("ftp://discord.example/api", TOKEN)
    with pytest.raises(api.DiscordRefused, match="no Discord bot token"):
        api.Client("https://discord.example/api", "  ")
    api.Client("https://discord.example/api/v10", TOKEN)                     # https anywhere is accepted
    c = api.Client("http://127.0.0.1:9/api", TOKEN)
    for bad in ("users/@me", "/a/../b", "/x://y"):
        with pytest.raises(api.DiscordError, match="bad API path"):
            c.get(bad)
    assert c.requests == 0


def test_no_answer_is_a_named_error_without_the_token():
    with FakeDiscord(TOKEN, {}) as fake:
        base = fake.base
    with pytest.raises(api.DiscordError, match="no answer") as e:           # the fake is gone
        api.Client(base, TOKEN, min_interval=0, timeout=5).get("/users/@me")
    assert TOKEN not in str(e.value)


# ------------------------------------------------------------------------------- from_profile

def test_from_profile_needs_the_recorded_clearance():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        prof = discord_fake.profile(capture="forbidden", api_base=fake.base, allow=["127.0.0.1"])
        with pytest.raises(api.DiscordRefused, match=r"capture = 'forbidden', so the API client is off"):
            api.from_profile(prof, environ={"CTF_DISCORD_TOKEN": TOKEN})
        assert fake.requests == []


def test_from_profile_needs_the_api_host_in_the_public_fetch_scope():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        prof = discord_fake.profile(capture="bot", api_base=fake.base, allow=[])
        with pytest.raises(api.DiscordRefused, match="rules.public_fetch_allow"):
            api.from_profile(prof, environ={"CTF_DISCORD_TOKEN": TOKEN})
        other = discord_fake.profile(capture="bot", api_base=fake.base, allow=["discord.example"])
        with pytest.raises(api.DiscordRefused, match="does not list it"):
            api.from_profile(other, environ={"CTF_DISCORD_TOKEN": TOKEN})
        assert fake.requests == []
    platform = discord_fake.profile(capture="bot", api_base="https://board.recon-test.example/api",
                                    allow=["board.recon-test.example"])
    with pytest.raises(api.DiscordRefused, match="event platform"):
        api.from_profile(platform, environ={"CTF_DISCORD_TOKEN": TOKEN})


def test_from_profile_reads_the_token_from_the_named_variable_only():
    with FakeDiscord(TOKEN, server_routes()) as fake:
        prof = discord_fake.profile(capture="bot", api_base=fake.base, allow=["127.0.0.1"],
                                    token_env="CTF_DISCORD_BOT")
        with pytest.raises(api.DiscordRefused, match=r"\$CTF_DISCORD_BOT is not set"):
            api.from_profile(prof, environ={"CTF_DISCORD_TOKEN": TOKEN, "CTF_TOKEN": "platform-credential"})
        assert fake.requests == []
        c = api.from_profile(prof, environ={"CTF_DISCORD_BOT": TOKEN, "CTF_TOKEN": "platform-credential"},
                             min_interval=0)
        assert c.get("/users/@me")["bot"] is True
        assert fake.requests[0].headers["authorization"] == "Bot " + TOKEN
