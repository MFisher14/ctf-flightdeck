"""CTFd adapter (API v1), ported from the carried client ctf/client.py behind PlatformAdapter.

    from ctf.platform import get_adapter
    plat = get_adapter(event.load("csctf"))      # never call make_adapter directly outside ctf/platform

Endpoints (CTFd API v1, under <base_url>/api/v1):
  list_challenges   GET  /challenges
  get_challenge     GET  /challenges/<id>
  download_files    GET  each entry of the challenge's "files" (site-root /files/... links)
  submit            POST /challenges/attempt {"challenge_id": <int>, "submission": <flag>}
  team_solves       GET  /teams/me/solves (a users-mode event answers 403/404: /users/me/solves)
  scoreboard        GET  /scoreboard
  challenge_solves  GET  /challenges/<id>/solves (every team's solve, earliest first: first blood; B-099)
  server_time       HEAD <base_url>/  (the Date header; ctf.dynamic aligns rotation windows to it)

Kept from the carried client: token auth ("Authorization: Token ..."), the session-cookie fallback
with the CSRF nonce scraped from the home page, the hard refusal of any hint unlock (POST /unlocks,
GET /hints/<id>: hints spend points and are the player's decision), and machine-wide submit pacing
(ctf.client.SubmitPacer: one flock-guarded queue per event host, a shared pause after a rate limit;
its interval is the profile's submit.interval_s). The team-wide queue with budget, dedupe and retry is
the gate's (ctf/platform/queue.py, B-006); this floor stays for the carried client.

Verdicts: correct, incorrect, already_solved, paused, ratelimited (HTTP 429, Retry-After honoured)
map onto SubmitStatus. "authentication_required" and the 403 "You have 0 tries remaining" (the
challenge's max_attempts is spent; CTFd did not judge the value) are NOT_ALLOWED. Any other word is
a PlatformError naming it: an unknown answer is never read as a verdict.

Credentials come from the environment only: CTF_TOKEN, else CTF_COOKIE (legacy CSCTF_* spellings are
read with a deprecation warning by ctf.env). They are never printed. A call without either fails
with a PlatformError naming both.

Container instances (per-team Docker plugins) are optional: make_adapter(profile, instances=cfg)
with cfg = {"endpoints": {"plugin": "docker_per_team"} | {...four routes...}, "cap": N | None}
returns CTFdInstanceAdapter, which implements InstanceCapability through ctf.instances (scope lock,
local cap, a refused start takes no slot) plus a `renew_instance` (B-003; not in the Protocol).
B-003 wired the plugin into the profile: make_adapter reads the event's `[instances]` section
(profile.instances.as_config()) when no explicit instances= is passed, so get_adapter(profile) yields
the instance adapter for an event that configures a plugin. An event with no `[instances]` section
still gets the plain adapter, whose instance calls raise InstancesUnavailable naming the missing config.
"""
from __future__ import annotations

import datetime as _dt
import email.utils
import re
import time
from pathlib import Path
from typing import Any, Callable, Mapping

import requests

from .. import env
from ..event import EventProfile
from . import _http
from .base import (INSTANCE_METHODS, Challenge, ChallengeSolve, FileRef, InstanceInfo,
                   InstancesUnavailable, NotAllowed, NotSupported, PlatformError, ScoreRow, SubmitResult,
                   SubmitStatus, TeamSolve)

DEFAULT_SUBMIT_INTERVAL_S = 3.0      # the carried client's submit_interval_min_s
DEFAULT_TIMEOUT_S = 20.0
USER_AGENT = "ctf-tools"

_VERDICTS = {
    "correct": SubmitStatus.CORRECT,
    "incorrect": SubmitStatus.INCORRECT,
    "already_solved": SubmitStatus.ALREADY_SOLVED,
    "paused": SubmitStatus.PAUSED,
    "ratelimited": SubmitStatus.RATE_LIMITED,
    "authentication_required": SubmitStatus.NOT_ALLOWED,
}
_NO_TRIES = re.compile(r"\b0 tries remaining\b", re.I)


class _HTTPStatus(PlatformError):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def _refuse_if_hint(path: str) -> None:
    p = path.split("?", 1)[0].rstrip("/")
    if p == "/unlocks" or (p.startswith("/hints/") and p != "/hints"):
        raise NotAllowed(f"{path} would unlock or fetch a paid hint and spend points; hints are the "
                         "player's decision, never the solver's")


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _tags(raw: Any) -> tuple[str, ...]:
    out = []
    for t in raw or ():
        v = t.get("value") if isinstance(t, dict) else t
        if isinstance(v, str) and v:
            out.append(v)
    return tuple(out)


def _int_id(challenge_id: str) -> int:
    try:
        return int(str(challenge_id))
    except ValueError:
        raise PlatformError(f"CTFd challenge ids are integers, got {challenge_id!r}") from None


class CTFdAdapter:
    kind = "ctfd"

    def __init__(self, base_url: str, *, token: str | None = None, cookie: str | None = None,
                 session: Any = None, anon_session: Any = None, submit_interval_s: float = DEFAULT_SUBMIT_INTERVAL_S,
                 pacer_state_dir: Path | None = None, timeout_s: float = DEFAULT_TIMEOUT_S,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time):
        if not base_url or not base_url.startswith(("http://", "https://")):
            raise PlatformError(f"CTFd base_url must be http(s), got {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.api = self.base_url + "/api/v1"
        self._token = token
        self._cookie = cookie
        self.timeout_s = timeout_s
        if session is None:
            session = requests.Session()
        self._s = session
        self._anon = anon_session      # off-origin file links: a session that carries no credentials
        self._s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        if token:
            self._s.headers["Authorization"] = "Token " + token
        elif cookie:
            self._s.cookies.set("session", cookie)
        self._csrf_loaded = False
        self._interval = submit_interval_s
        self._pacer_state_dir = pacer_state_dir
        self._sleep, self._clock = sleep, clock
        self._pacer = None

    # ------------------------------------------------------------------------------- plumbing
    @property
    def pacer(self):
        if self._pacer is None:
            from ..client import SubmitPacer   # the carried machine-wide pacing floor (B-006 extends it)
            self._pacer = SubmitPacer(self.base_url, self._interval, state_dir=self._pacer_state_dir,
                                      sleep=self._sleep, clock=self._clock)
        return self._pacer

    def _require_auth(self, call: str) -> None:
        if not self._token and not self._cookie:
            raise PlatformError(f"{call}: no CTFd credentials; set CTF_TOKEN (an access token from the "
                                "CTFd settings page) or CTF_COOKIE (the logged-in session cookie)")

    def _load_csrf(self) -> None:
        """Cookie auth needs CTFd's CSRF nonce on POSTs; it is on the home page as csrfNonce."""
        if self._csrf_loaded or self._token or not self._cookie:
            return
        r = self._s.request("GET", self.base_url + "/", timeout=self.timeout_s)
        if r.status_code != 200:
            raise PlatformError(f"cookie auth: GET / -> HTTP {r.status_code} while reading the CSRF nonce")
        m = re.search(r"['\"]csrfNonce['\"]\s*:\s*['\"]([0-9a-f]+)['\"]", r.text or "")
        if not m:
            raise PlatformError("cookie auth: no csrfNonce on the CTFd home page (session expired?)")
        self._s.headers["CSRF-Token"] = m.group(1)
        self._s.headers["X-CSRF-Token"] = m.group(1)
        self._csrf_loaded = True

    def _call(self, method: str, path: str, call: str, *, json: dict | None = None,
              site_root: bool = False, allow: tuple[int, ...] = (200,),
              bodyless: tuple[int, ...] = ()) -> tuple[Any, Any]:
        _refuse_if_hint(path)
        self._require_auth(call)
        if method != "GET":
            self._load_csrf()
        url = (self.base_url if site_root else self.api) + path
        try:
            r = self._s.request(method, url, json=json, timeout=self.timeout_s)
        except (requests.RequestException, OSError) as e:
            raise PlatformError(f"{call}: {method} {path} failed ({type(e).__name__})") from e
        if r.status_code not in allow:
            raise _HTTPStatus(f"{call}: {method} {path} -> HTTP {r.status_code}", r.status_code)
        if r.status_code in bodyless:
            try:
                return r, r.json()
            except ValueError:
                return r, None      # e.g. a proxy's plain-text 429: the status code says enough
        body = _http.json_body(r, call)
        if isinstance(body, dict) and body.get("success") is False and "data" not in body:
            raise PlatformError(f"{call}: {method} {path}: {body.get('errors') or body.get('message')}")
        return r, body

    def _data(self, path: str, call: str) -> Any:
        return self._call("GET", path, call)[1].get("data")

    # ------------------------------------------------------------------------------- reads
    def list_challenges(self) -> list[Challenge]:
        rows = self._data("/challenges", "list_challenges") or []
        return [Challenge(id=str(c["id"]), name=str(c.get("name") or c["id"]),
                          category=str(c.get("category") or ""), points=c.get("value"),
                          solved_by_team=bool(c.get("solved_by_me")), tags=_tags(c.get("tags")), raw=c)
                for c in rows]

    def get_challenge(self, challenge_id: str) -> Challenge:
        cid = _int_id(challenge_id)
        c = self._data(f"/challenges/{cid}", "get_challenge") or {}
        files = tuple(FileRef(name=_http.safe_filename(f), url=f) for f in c.get("files") or ())
        return Challenge(id=str(c.get("id", cid)), name=str(c.get("name") or cid),
                         category=str(c.get("category") or ""), points=c.get("value"),
                         description=c.get("description") or "", files=files,
                         connection_info=c.get("connection_info") or "",
                         solved_by_team=bool(c.get("solved_by_me")), tags=_tags(c.get("tags")), raw=c)

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        """Every file of the challenge into dest. A site-relative link goes through the authenticated
        session; an absolute link on another origin (an object store) is fetched WITHOUT the CTFd
        credentials, which must never leave the platform host."""
        ch = self.get_challenge(challenge_id)
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        written = []
        for ref in ch.files:
            url = ref.url or ""
            if url.startswith("/"):
                url = self.base_url + url
            elif not url.startswith(("http://", "https://")):
                raise PlatformError(f"download_files: challenge {ch.id} lists a file link {url!r} "
                                    "that is neither site-relative nor http(s)")
            if _http.origin(url) == _http.origin(self.base_url):
                r = self._s.request("GET", url, timeout=max(60.0, self.timeout_s), stream=True)
            else:
                if self._anon is None:
                    self._anon = requests.Session()
                r = self._anon.request("GET", url, timeout=max(60.0, self.timeout_s), stream=True)
            try:
                if r.status_code != 200:
                    raise PlatformError(f"download_files: {ref.name} of challenge {ch.id} -> "
                                        f"HTTP {r.status_code}")
                out = _http.unique_path(dest, ref.name)
                _http.write_body(r, out)
            finally:
                close = getattr(r, "close", None)
                if close:
                    close()
            written.append(out)
        return written

    def team_solves(self) -> list[TeamSolve]:
        try:
            rows = self._call("GET", "/teams/me/solves", "team_solves")[1].get("data") or []
        except _HTTPStatus as e:
            if e.status not in (400, 403, 404):
                raise
            rows =self._data("/users/me/solves", "team_solves") or []   # users-mode event
        out = []
        for row in rows:
            cid = row.get("challenge_id") or (row.get("challenge") or {}).get("id")
            if cid is None:
                continue
            user = row.get("user") or {}
            out.append(TeamSolve(challenge_id=str(cid),
                                 solver=user.get("name") if isinstance(user, dict) else None,
                                 at=_epoch(row.get("date"))))
        return out

    def scoreboard(self) -> list[ScoreRow]:
        rows = self._data("/scoreboard", "scoreboard") or []
        return [ScoreRow(rank=int(r.get("pos") or i), team=str(r.get("name") or ""),
                         score=int(r.get("score") or 0)) for i, r in enumerate(rows, 1)]

    def challenge_solves(self, challenge_id: str) -> list[ChallengeSolve]:
        """Every account's solve of one challenge, earliest first (B-099): the first is its first
        blood. HTTP 403 (scores hidden, or solves not shown to this account) is NotSupported naming
        it; any other failure a PlatformError. A row with no account name is a PlatformError: a
        nameless solve could be ours or a rival's, so it is never guessed."""
        cid = _int_id(challenge_id)
        try:
            rows = self._call("GET", f"/challenges/{cid}/solves", "challenge_solves")[1].get("data") or []
        except _HTTPStatus as e:
            if e.status == 403:
                raise NotSupported(f"challenge_solves: GET /challenges/{cid}/solves -> HTTP 403: this CTFd "
                                   "does not show solves to this account (scores hidden?)") from None
            raise
        if not isinstance(rows, list):
            raise PlatformError(f"challenge_solves: GET /challenges/{cid}/solves answered "
                                f"{type(rows).__name__}, not a list of solves")
        out = []
        for r in rows:
            name = r.get("name") if isinstance(r, dict) else None
            if not isinstance(name, str) or not name:
                raise PlatformError(f"challenge_solves: a solve of challenge {cid} names no account")
            aid = r.get("account_id")
            out.append(ChallengeSolve(challenge_id=str(cid), account=name, at=_epoch(r.get("date")),
                                      account_id=str(aid) if aid is not None else None))
        out.sort(key=lambda s: (s.at is None, s.at or 0.0))
        return out

    def server_time(self) -> float:
        """The platform's clock (epoch seconds) from one HEAD of the site root's Date header. The
        header has whole seconds, so half a second is added (the middle of that second)."""
        try:
            r = self._s.request("HEAD", self.base_url + "/", timeout=self.timeout_s)
        except (requests.RequestException, OSError) as e:
            raise PlatformError(f"server_time: HEAD / failed ({type(e).__name__})") from e
        date = (getattr(r, "headers", None) or {}).get("Date")
        if not date:
            raise PlatformError(f"server_time: HEAD / -> HTTP {r.status_code} with no Date header")
        try:
            return email.utils.parsedate_to_datetime(date).timestamp() + 0.5
        except (TypeError, ValueError):
            raise PlatformError(f"server_time: unparseable Date header {date!r}") from None

    # ------------------------------------------------------------------------------- submit
    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        """The raw POST, paced machine-wide. Only the SubmitGate calls this."""
        cid = _int_id(challenge_id)
        with self.pacer.slot() as slot:
            r, body = self._call("POST", "/challenges/attempt", "submit",
                                 json={"challenge_id": cid, "submission": flag}, allow=(200, 403, 429),
                                 bodyless=(429,))
            data = body.get("data") if isinstance(body, dict) else None
            word = str(data.get("status", "")) if isinstance(data, dict) else ""
            if r.status_code == 429:
                word = "ratelimited"
            slot.record(word or "unknown")
        message = str(data.get("message", "")) if isinstance(data, dict) else ""
        if r.status_code == 403 and word == "incorrect" and _NO_TRIES.search(message):
            return SubmitResult(SubmitStatus.NOT_ALLOWED, message)
        status = _VERDICTS.get(word)
        if status is None:
            raise PlatformError(f"submit: challenge {cid} answered HTTP {r.status_code} with status "
                                f"{word or '(none)'!r}, which is not a CTFd verdict")
        retry = _http.retry_after(r) if status is SubmitStatus.RATE_LIMITED else None
        return SubmitResult(status, message, retry_after=retry)

    # ------------------------------------------------------------------------------- instances
    def __getattr__(self, name: str):
        if name in INSTANCE_METHODS:
            raise InstancesUnavailable(
                f"{name}: no container-plugin configured for this CTFd event; add an [instances] "
                "section to the event profile (B-003) or pass make_adapter(profile, instances={...})")
        raise AttributeError(name)


class _ScopeView:
    """What ctf.instances.Instances needs for its scope lock: the released challenges, int ids."""

    def __init__(self, adapter: CTFdAdapter):
        self._a = adapter

    def challenges(self) -> list[dict]:
        return [{"id": int(c.id)} for c in self._a.list_challenges()]


class CTFdInstanceAdapter(CTFdAdapter):
    """CTFd plus a per-team container plugin (InstanceCapability)."""

    def __init__(self, base_url: str, *, instances: Mapping[str, Any], **kw):
        super().__init__(base_url, **kw)
        from ..instances import InstanceError, Instances
        self._InstanceError = InstanceError
        try:
            self._inst = Instances.from_config(_ScopeView(self), instances, transport=self._plugin_call)
        except InstanceError as e:
            raise PlatformError(f"instance plugin config: {e}") from None

    def _plugin_call(self, method: str, path: str, json: dict | None) -> Any:
        site_root = self._inst.ep.site_root
        # 400 is how docker_per_team refuses a start ("Max containers (3) reached"); Instances reads it.
        return self._call(method, path, f"instance {method} {path}", json=json, site_root=site_root,
                          allow=(200, 400, 403, 429))[1]

    def _info(self, challenge_id: str, info: dict, default_state: str) -> InstanceInfo:
        connect = info.get("connect")
        rem = info.get("remaining")
        expires = None
        if isinstance(rem, (int, float)) and not isinstance(rem, bool):
            expires = self._clock() + float(rem) if rem < 10**9 else float(rem)
        if info.get("error") is not None:
            state = "unknown"
        else:
            state = default_state if (connect or default_state == "stopped") else "unknown"
        return InstanceInfo(challenge_id=str(challenge_id), state=state,
                            connection_info=str(connect or ""), expires_at=expires)

    def _run(self, fn, challenge_id: str):
        try:
            return fn(_int_id(challenge_id))
        except self._InstanceError as e:
            raise PlatformError(str(e)) from None

    def start_instance(self, challenge_id: str) -> InstanceInfo:
        return self._info(challenge_id, self._run(self._inst.spawn, challenge_id), "running")

    def instance_status(self, challenge_id: str) -> InstanceInfo:
        return self._info(challenge_id, self._run(self._inst.status, challenge_id), "running")

    def stop_instance(self, challenge_id: str) -> InstanceInfo:
        self._run(self._inst.stop, challenge_id)
        return InstanceInfo(challenge_id=str(challenge_id), state="stopped")

    def renew_instance(self, challenge_id: str) -> InstanceInfo:
        """Extend our running instance's clock (B-003; not in the InstanceCapability Protocol — the
        scheduler calls it through duck typing when the plugin offers a renew route)."""
        return self._info(challenge_id, self._run(self._inst.renew, challenge_id), "running")


def make_adapter(profile: EventProfile, *, instances: Mapping[str, Any] | None = None,
                 session: Any = None, environ: Mapping[str, str] | None = None,
                 **kw) -> CTFdAdapter:
    if profile.platform.kind != "ctfd":
        raise PlatformError(f"ctfd adapter asked for a {profile.platform.kind!r} event")
    if profile.rules.ai_on_platform == "forbidden":
        raise NotAllowed(f"event {profile.slug!r} forbids automation on the platform; use manual mode")
    base_url = profile.platform.base_url or ""
    override = env.get("CTF_PLATFORM_URL", environ=environ)
    if override and override.rstrip("/") != base_url.rstrip("/"):
        raise PlatformError("CTF_PLATFORM_URL is set and differs from the event profile's "
                            f"platform.base_url ({base_url}); the profile is the one source, so edit it "
                            "(or unset CTF_PLATFORM_URL)")
    kw.setdefault("submit_interval_s", profile.submit.interval_s)
    token = env.get("CTF_TOKEN", environ=environ)
    cookie = env.get("CTF_COOKIE", environ=environ)
    token = _http.check_secret(token, "CTF_TOKEN") if token else None
    cookie = _http.check_secret(cookie, "CTF_COOKIE") if cookie else None
    # B-003: with no explicit instances= (the normal get_adapter path), take the plugin wiring from the
    # event profile's [instances] section when it has one. An explicit argument still wins (tests).
    if instances is None and profile.instances is not None:
        instances = profile.instances.as_config()
    if instances is not None:
        return CTFdInstanceAdapter(base_url, instances=instances, token=token, cookie=cookie,
                                   session=session, **kw)
    return CTFdAdapter(base_url, token=token, cookie=cookie, session=session, **kw)
