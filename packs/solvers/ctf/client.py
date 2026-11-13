"""A thin CTFd API v1 client for CSCTF 2026.

Only the endpoints a player needs: list challenges, read one, download its files, submit a flag,
read the team's own solves, and read the scoreboard. It is deliberately read-mostly and paced; it
never scans, never enumerates other teams' instances, and only ever POSTs to the one submit endpoint.

Auth is a CTFd access token sent as `Authorization: Token <token>` (CTFd's scheme). Create the token
in the web UI once the event opens; see ctf/config.py.

Manual mode is code-enforced here (R-02, ctf/platform/legacy.py): a CTFd client is built only for an
event profile (the one passed, else ctf.event.current()) whose rules let automation reach a CTFd
platform. A manual event (platform kind manual, or ai_on_platform forbidden) raises NotAllowed in the
constructor, before any requests.Session exists; submit() also refuses submit_mode manual. A missing
profile is refused too (fail closed), and a non-CTFd platform is NotSupported.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from . import config as _config
from .event import EventProfile
from .platform import legacy as _legacy


class CTFdError(RuntimeError):
    pass


# ---------------------------------------------------------------- cross-process submit pacing
# Pacing used to live on the client object (`_last_submit`), so ~20 parallel solver processes did not
# pace each other and wave 1 sat in "You're submitting flags too fast" for ~15 minutes. Every CTFd
# client on this machine now goes through one flock-guarded state file per event host: the lock is held
# from the pacing wait through the POST, so submits from all processes form a single queue, at least
# `submit_interval_min_s` apart, and a `ratelimited` verdict pauses every process, not just the one that
# saw it. (The full queue with per-minute budget and auto-retry is B-006; this is the pacing floor.)
SUBMIT_STATE_ENV = "CTF_SUBMIT_STATE_DIR"
RATELIMIT_PAUSE_S = 20.0       # every process waits this long after any process sees `ratelimited`
RATELIMIT_PAUSE_MAX_S = 120.0  # the pause doubles on repeated rate limits, up to this


def submit_state_dir() -> Path:
    """Machine-wide directory for the shared submit-pacing state ($CTF_SUBMIT_STATE_DIR, else the
    user cache dir). Shared by every checkout and worktree, which is the point."""
    env = os.environ.get(SUBMIT_STATE_ENV)
    if env:
        return Path(env)
    cache = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(cache) / "ctf-tools" / "submit-pace"


class SubmitPacer:
    """One flock-guarded JSON state file per event host. Use `with pacer.slot(): <POST>`; call
    `record(status)` inside the slot with the verdict. Keyed by host only (no auth material touches the
    state), so every account on this machine submitting to one event shares one queue."""

    def __init__(self, base_url: str, interval_s: float, state_dir: Path | None = None,
                 sleep=time.sleep, clock=time.time):
        self.interval_s = float(interval_s)
        key = hashlib.sha256(base_url.rstrip("/").lower().encode("utf-8")).hexdigest()[:16]
        d = Path(state_dir) if state_dir is not None else submit_state_dir()
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise CTFdError(f"submit pacing state dir {d} is unusable ({e}); set ${SUBMIT_STATE_ENV} "
                            f"to a writable directory. Refusing to submit unpaced.") from e
        self.state_path = d / f"{key}.json"
        self.lock_path = d / f"{key}.lock"
        self._sleep = sleep
        self._clock = clock
        self._held: dict | None = None

    def _read(self) -> dict:
        try:
            st = json.loads(self.state_path.read_text(encoding="utf-8"))
            return st if isinstance(st, dict) else {}
        except FileNotFoundError:
            return {}
        except ValueError:
            # A torn/corrupt state file must not wedge the queue; the lock still serializes us and the
            # next write repairs it. Pace conservatively: treat the last submit as "just now".
            return {"last_submit": self._clock()}

    def _write(self, st: dict) -> None:
        tmp = self.state_path.with_suffix(f".tmp{os.getpid()}")
        tmp.write_text(json.dumps(st), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def wait_s(self, st: dict, now: float) -> float:
        """Seconds to wait before the next POST, given the shared state."""
        gap = float(st.get("last_submit", 0.0)) + self.interval_s - now
        pause = float(st.get("blocked_until", 0.0)) - now
        return max(0.0, gap, pause)

    @contextlib.contextmanager
    def slot(self):
        with open(self.lock_path, "a+") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                while True:
                    st = self._read()
                    w = self.wait_s(st, self._clock())
                    if w <= 0:
                        break
                    self._sleep(w)
                self._held = st
                try:
                    yield self
                finally:
                    # Stamp even when the POST raised: it may still have reached the server.
                    st = dict(self._held)
                    st["last_submit"] = self._clock()
                    self._write(st)
            finally:
                self._held = None
                fcntl.flock(lf, fcntl.LOCK_UN)

    def record(self, status: str) -> None:
        """Fold one verdict into the shared state (call inside `slot`)."""
        if self._held is None:
            raise RuntimeError("SubmitPacer.record called outside slot()")
        now = self._clock()
        if status == "ratelimited":
            prev = float(self._held.get("pause_s", 0.0))
            pause = min(RATELIMIT_PAUSE_MAX_S, prev * 2 if prev else RATELIMIT_PAUSE_S)
            self._held["pause_s"] = pause
            self._held["blocked_until"] = now + pause
        else:
            self._held["pause_s"] = 0.0


@dataclass
class Submission:
    status: str          # correct | incorrect | already_solved | paused | ratelimited | authentication_required
    message: str

    @property
    def correct(self) -> bool:
        return self.status in ("correct", "already_solved")

    @property
    def already(self) -> bool:
        return self.status == "already_solved"


class CTFd:
    def __init__(self, cfg: _config.Config | None = None, *, profile: EventProfile | None = None):
        # R-02: the event's rules are checked before any session (and so any socket) exists.
        self.profile = _legacy.require("CTFd client", profile=profile)
        self.cfg = cfg or _config.load()
        self.api = self.cfg.base_url + "/api/v1"
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": self.cfg.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        if self.cfg.token:
            # API-token auth bypasses CSRF — the clean path for scripting.
            self.s.headers["Authorization"] = "Token " + self.cfg.token
        elif self.cfg.cookie:
            # Session-cookie fallback (tokens UI disabled). CTFd requires a CSRF nonce on POSTs when
            # authenticated by cookie; scrape it from the homepage and send it as X-CSRF-Token.
            self.s.cookies.set("session", self.cfg.cookie)
            self._load_csrf()
        self._pacer: SubmitPacer | None = None

    @property
    def pacer(self) -> SubmitPacer:
        if self._pacer is None:
            self._pacer = SubmitPacer(self.cfg.base_url, self.cfg.submit_interval_min_s)
        return self._pacer

    def _load_csrf(self) -> None:
        try:
            r = self.s.get(self.cfg.base_url + "/", timeout=self.cfg.request_timeout_s)
            m = re.search(r"['\"]csrfNonce['\"]\s*:\s*['\"]([0-9a-f]+)['\"]", r.text)
            if m:
                self.s.headers["CSRF-Token"] = m.group(1)
                self.s.headers["X-CSRF-Token"] = m.group(1)
        except requests.RequestException:
            pass

    # ---------------------------------------------------------------- low level
    # HARD RULE: never spend points on hints. CTFd deducts points when a hint is unlocked
    # (POST /unlocks) or its paid content is fetched (GET /hints/{id}). Buying a hint is a human
    # decision, never the solver's (one hint = ~10-20 pts; 2025 1st place won by 10). These guards
    # make an accidental spend impossible from this client.
    def _refuse_if_hint(self, path: str) -> None:
        p = path.split("?", 1)[0].rstrip("/")
        if p == "/unlocks" or (p.startswith("/hints/") and p != "/hints"):
            raise CTFdError(
                f"blocked: {path} would unlock/fetch a paid hint and spend points. Hints are a human "
                f"decision, never the solver's (AGENTS.md). Ask the player if a hint is truly wanted."
            )

    def _get(self, path: str, **kw) -> Any:
        self._refuse_if_hint(path)
        r = self.s.get(self.api + path, timeout=self.cfg.request_timeout_s, **kw)
        return self._envelope(r)

    def _post(self, path: str, json: dict) -> Any:
        self._refuse_if_hint(path)
        r = self.s.post(self.api + path, json=json, timeout=self.cfg.request_timeout_s)
        return self._envelope(r, allow_status=(200, 403, 429))

    @staticmethod
    def _envelope(r: requests.Response, allow_status=(200,)) -> Any:
        if r.status_code not in allow_status:
            raise CTFdError(f"{r.request.method} {r.url} -> HTTP {r.status_code}: {r.text[:200]}")
        try:
            body = r.json()
        except ValueError:
            raise CTFdError(f"{r.url}: non-JSON response (HTTP {r.status_code}); not logged in?")
        if isinstance(body, dict) and body.get("success") is False and "data" not in body:
            raise CTFdError(f"{r.url}: {body.get('errors') or body.get('message') or body}")
        return body

    # ---------------------------------------------------------------- reads
    def me(self) -> dict:
        """The authenticated user (confirms the token works)."""
        return self._get("/users/me")["data"]

    def tokens(self) -> list[dict]:
        """The account's API tokens (id, type, expiration; CTFd never returns token values here).
        Read by the doctor's token-expiry check (B-190)."""
        return self._get("/tokens")["data"]

    def team(self) -> dict | None:
        try:
            return self._get("/teams/me")["data"]
        except CTFdError:
            return None

    def challenges(self) -> list[dict]:
        """All challenges visible to us right now (id, name, category, value, solved_by_me, tags)."""
        return self._get("/challenges")["data"]

    def challenge(self, cid: int) -> dict:
        """Full detail for one challenge: description, category, value, files, connection_info, hints, tags."""
        return self._get(f"/challenges/{cid}")["data"]

    def team_solved_ids(self) -> set[int]:
        """Challenge ids the team (or solo account) has already solved — so we never re-work them."""
        try:
            data = self._get("/teams/me/solves")["data"]
        except CTFdError:
            data = self._get("/users/me/solves")["data"]
        out = set()
        for row in data:
            cid = (row.get("challenge_id") or (row.get("challenge") or {}).get("id"))
            if cid is not None:
                out.add(int(cid))
        return out

    def scoreboard(self) -> list[dict]:
        return self._get("/scoreboard")["data"]

    # ---------------------------------------------------------------- files
    def download_files(self, cid: int, dest: Path) -> list[Path]:
        """Download every file attached to challenge `cid` into `dest`. Returns the written paths."""
        dest.mkdir(parents=True, exist_ok=True)
        detail = self.challenge(cid)
        written = []
        for rel in detail.get("files") or []:
            url = self.cfg.base_url + rel if rel.startswith("/") else rel
            name = rel.split("?", 1)[0].rstrip("/").split("/")[-1] or "file.bin"
            out = dest / name
            with self.s.get(url, stream=True, timeout=max(60.0, self.cfg.request_timeout_s)) as r:
                if r.status_code != 200:
                    raise CTFdError(f"download {url} -> HTTP {r.status_code}")
                with open(out, "wb") as fh:
                    for chunk in r.iter_content(65536):
                        fh.write(chunk)
            written.append(out)
        return written

    # ---------------------------------------------------------------- submit
    def submit(self, cid: int, flag: str) -> Submission:
        """POST one flag to the one submit endpoint. Paced machine-wide (SubmitPacer: one queue for every
        process on this host, at least submit_interval_min_s apart, shared pause after a rate limit) to
        respect the event's no-flooding rule.

        This is the raw call; routine play should go through ctf.submit.guarded_submit, which also
        dedupes tried flags and stops after repeated wrong answers. Never call this in a loop over
        candidate flags — that is flag brute-forcing, which the rules forbid.

        Refused (NotAllowed, nothing sent) when the event's rules make submission manual."""
        _legacy.check(self.profile, "CTFd.submit", submit=True)
        with self.pacer.slot() as slot:
            body = self._post("/challenges/attempt", {"challenge_id": int(cid), "submission": flag})
            data = body.get("data") or {}
            sub = Submission(status=str(data.get("status", "unknown")), message=str(data.get("message", "")))
            slot.record(sub.status)
        return sub


def connect(cfg: _config.Config | None = None, *, profile: EventProfile | None = None) -> CTFd:
    return CTFd(cfg, profile=profile)
