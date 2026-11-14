"""A loopback stand-in for the Discord REST API (B-112 tests). Not a test module.

    with discord_fake.FakeDiscord(TOKEN, routes) as api:
        client = discordapi.Client(api.base, TOKEN, min_interval=0)
        ...
        api.requests            # [Request(method, path, query, headers)], in arrival order

`routes` maps a path under the API base ("/guilds/1/channels") to a JSON-able value (served 200),
to a `(status, value)` or `(status, value, headers)` tuple, or to a `Seq([...])` of those, served one
per request with the last one repeating (a plain list is a JSON array). A path with no route is a 404 in Discord's error shape. Every
request must carry `Authorization: Bot <token>`; anything else is a 401 whose message echoes what was
sent, the way a careless server might, so a test can prove the client scrubs it.

It listens on 127.0.0.1 only, on a port the OS picks, and serves from a daemon thread.
"""
from __future__ import annotations

import json
import threading
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PREFIX = "/api/v10"


class Seq(list):
    """Answers served one per request to the same path; the last one repeats."""


@dataclass(frozen=True)
class Request:
    method: str
    path: str                 # under the API base, e.g. "/users/@me"; the raw path when outside it
    query: dict
    headers: dict             # lower-cased names


class FakeDiscord:
    def __init__(self, token: str, routes: dict, *, prefix: str = PREFIX):
        self.token, self.routes, self.prefix = token, dict(routes), prefix
        self.requests: list[Request] = []
        self._served: dict[str, int] = {}
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):          # keep the test output clean
                pass

            def _serve(self):
                parts = urllib.parse.urlsplit(self.path)
                path = parts.path[len(fake.prefix):] if parts.path.startswith(fake.prefix) else parts.path
                query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
                headers = {k.lower(): v for k, v in self.headers.items()}
                with fake._lock:
                    fake.requests.append(Request(self.command, path, query, headers))
                    n = fake._served.get(path, 0)
                    fake._served[path] = n + 1
                if self.command != "GET":
                    return self._send(405, {"message": "405: Method Not Allowed", "code": 0})
                sent = headers.get("authorization", "")
                if sent != "Bot " + fake.token:
                    return self._send(401, {"message": f"401: Unauthorized ({sent})", "code": 0})
                if path not in fake.routes:
                    return self._send(404, {"message": "404: Not Found", "code": 0})
                spec = fake.routes[path]
                if isinstance(spec, Seq):
                    spec = spec[min(n, len(spec) - 1)]
                status, value, extra = 200, spec, {}
                if isinstance(spec, tuple):
                    status, value = spec[0], spec[1]
                    extra = spec[2] if len(spec) > 2 else {}
                self._send(status, value, extra)

            def _send(self, status, value, extra=None):
                body = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, str(v))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01},
                                        daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    @property
    def base(self) -> str:
        return self.origin + self.prefix

    def paths(self) -> list[str]:
        return [r.path for r in self.requests]

    def __enter__(self) -> "FakeDiscord":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def msg(mid: int, content: str, author: str = "organizer", **extra) -> dict:
    return {"id": str(mid), "content": content, "author": {"id": "900", "username": author}, **extra}


GUILD = "424242"


def profile(*, capture: str = "forbidden", api_base: str | None = None, allow=(), guild_id: str | None = None,
            token_env: str | None = None, flag_sharing: str = "allowed", slug: str = "recon-test"):
    """A synthetic event profile (flag prefix RECON) with the given [discord] table."""
    import datetime as dt

    from ctf import event
    discord = {"capture": capture}
    if api_base is not None:
        discord["api_base"] = api_base
    if guild_id is not None:
        discord["guild_id"] = guild_id
    if token_env is not None:
        discord["token_env"] = token_env
    return event.parse({
        "slug": slug, "name": "Recon Test", "dates": {"start": dt.date(2027, 1, 1), "end": dt.date(2027, 1, 3)},
        "platform": {"kind": "ctfd", "base_url": "https://board.recon-test.example"},
        "flag": {"prefixes": ["RECON"]},
        "rules": {"submit_mode": "manual", "flag_sharing": flag_sharing, "ai_on_platform": "allowed",
                  "public_fetch_allow": list(allow)},
        "discord": discord,
    }, src="tests/discord_fake.py")


def server_routes() -> dict:
    """A small server: a hidden channel whose topic holds a recognition word, a rules channel whose
    messages spell a flag by their first characters, a pin, expressions, a bot with a description."""
    rules = [msg(5001 + n, text) for n, text in enumerate([
        "Welcome aboard. Flag format: RECON{example_flag_here}",
        "Respect everyone", "Every team has four players", "Cheating is forbidden", "Only attack your targets",
        "No flag sharing", "{ braces are not brackets", "Ask in #help", "4 hours of sleep is not enough",
        "} that is all"])]
    return {
        "/users/@me": {"id": "777", "username": "recon-bot", "bot": True},
        f"/guilds/{GUILD}": {
            "id": GUILD, "name": "Recon Test Fleet", "description": "The fleet's home port",
            "rules_channel_id": "11",
            "roles": [{"id": GUILD, "name": "@everyone", "position": 0},
                      {"id": "31", "name": "Watch Officer", "position": 2},
                      {"id": "32", "name": "Deckhand", "position": 1}],
            "emojis": [{"id": "41", "name": "RECONwish_granted"}, {"id": "40", "name": "anchor"}],
            "stickers": [{"id": "45", "name": "lighthouse", "description": "a light in the fog", "tags": "beacon"}],
        },
        f"/guilds/{GUILD}/channels": [
            {"id": "10", "type": 4, "name": "Bridge", "position": 0},
            {"id": "12", "type": 0, "name": "watch", "position": 2, "parent_id": "10",
             "topic": "The watch is broadcasting. Recognition word: **halyard**"},
            {"id": "11", "type": 0, "name": "rules", "position": 1, "parent_id": "10", "topic": "Read me"},
            {"id": "13", "type": 0, "name": "locked", "position": 3, "topic": "staff only"},
            {"id": "14", "type": 15, "name": "help", "position": 4, "topic": "Post guidelines",
             "available_tags": [{"id": "1", "name": "solved"}, {"id": "2", "name": "open"}]},
            {"id": "15", "type": 2, "name": "Voice", "position": 5},
        ],
        f"/guilds/{GUILD}/threads/active": {"threads": [
            {"id": "60", "type": 11, "name": "side quest", "parent_id": "12"}], "members": []},
        f"/guilds/{GUILD}/scheduled-events": [
            {"id": "70", "name": "Kickoff", "description": "Opening call",
             "entity_metadata": {"location": "the main deck"}}],
        f"/guilds/{GUILD}/soundboard-sounds": {"items": [{"sound_id": "80", "name": "foghorn"}]},
        f"/guilds/{GUILD}/onboarding": {"prompts": [
            {"id": "1", "title": "Pick your station",
             "options": [{"title": "Engine room", "description": "keep it running"}]}]},
        f"/guilds/{GUILD}/welcome-screen": {"description": "Fall in with the fleet",
                                            "welcome_channels": [{"channel_id": "11", "description": "Start here"}]},
        f"/guilds/{GUILD}/members": [
            {"user": {"id": "900", "username": "organizer"}, "nick": "The Admiral"},
            {"user": {"id": "901", "username": "watchtower", "bot": True}}],
        "/applications/901/rpc": {"id": "901", "name": "Watchtower",
                                  "description": "I keep the watch. RECON{b0t_ab0ut_m3}"},
        # Discord answers newest first: the capture must put them back in posting order
        "/channels/11/messages": list(reversed(rules)),
        "/channels/11/pins": [],
        "/channels/12/messages": [msg(6002, "second"), msg(6001, "first", embeds=[
            {"title": "Signal", "description": "embedded line", "fields": [{"name": "k", "value": "v"}],
             "footer": {"text": "foot"}}])],
        "/channels/12/pins": [msg(6001, "pinned order of the day")],
        "/channels/13/messages": (403, {"message": "Missing Access", "code": 50001}),
        "/channels/13/pins": (403, {"message": "Missing Access", "code": 50001}),
        "/channels/60/messages": [msg(6101, "thread opener")],
        "/channels/60/pins": [],
    }
