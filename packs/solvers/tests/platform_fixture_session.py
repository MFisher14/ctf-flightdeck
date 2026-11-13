"""A recorded-fixture stand-in for requests.Session, for the platform adapter contract tests (B-005).

Fixtures are hand-written JSON files under tests/fixtures/platform/ (written from the CTFd API v1
docs, the carried ctf/client.py and ctf/instances.py, and the Huntress gm.py/fakegm.py wire notes).
Each route is
    {"method": "GET", "url": "<absolute url without query>", "params": {...subset of the query},
     "json": {...exact body, optional}, "status": 200, "headers": {...},
     "body": <json> | "text": "..." | "bytes_hex": "..."}
A request that matches no route fails the test: nothing here ever touches the network.
"""
from __future__ import annotations

import json as _json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "platform"


def load(name: str) -> dict:
    return _json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeResponse:
    def __init__(self, route: dict, url: str):
        self.status_code = route.get("status", 200)
        self.headers = dict(route.get("headers") or {})
        self.url = url
        if "body" in route:
            self.content = _json.dumps(route["body"]).encode()
            self._json = route["body"]
        elif "bytes_hex" in route:
            self.content = bytes.fromhex(route["bytes_hex"])
            self._json = None
        else:
            self.content = (route.get("text") or "").encode()
            self._json = None
        self.text = self.content.decode("utf-8", "replace")
        self.closed = False

    def json(self):
        if self._json is None:
            raise ValueError("not JSON")
        return self._json

    def iter_content(self, size=65536):
        for i in range(0, len(self.content), size):
            yield self.content[i:i + size]

    def close(self):
        self.closed = True


class _Cookies(dict):
    def set(self, name, value):
        self[name] = value


class FakeSession:
    def __init__(self, routes: list[dict]):
        self.routes = [dict(r) for r in routes]
        self.headers: dict[str, str] = {}
        self.cookies = _Cookies()
        self.trust_env = True
        self.calls: list[dict] = []

    def add(self, *routes: dict) -> "FakeSession":
        # Later routes win: an override goes in front.
        self.routes = [dict(r) for r in routes] + self.routes
        return self

    def request(self, method, url, params=None, json=None, data=None, headers=None, timeout=None,
                stream=False, **kw):
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query))
        query.update({str(k): str(v) for k, v in (params or {}).items()})
        bare = f"{parts.scheme}://{parts.netloc}{parts.path}"
        self.calls.append({"method": method.upper(), "url": bare, "params": query, "json": json,
                           "headers": dict(self.headers, **(headers or {}))})
        for i, r in enumerate(self.routes):
            if r["method"].upper() != method.upper() or r["url"] != bare:
                continue
            if any(query.get(k) != str(v) for k, v in (r.get("params") or {}).items()):
                continue
            if "json" in r and r["json"] != json:
                continue
            if r.get("once"):
                self.routes.pop(i)
            return FakeResponse(r, url)
        raise AssertionError(f"no fixture route for {method} {bare} params={query} json={json}")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def sent(self, method=None, url=None):
        return [c for c in self.calls if (method is None or c["method"] == method)
                and (url is None or c["url"] == url)]
