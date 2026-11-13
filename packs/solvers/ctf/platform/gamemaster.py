"""Game Master adapter (the Huntress CTF platform), ported from huntress:tools/gm.py.

The Game Master is one URL (the profile's platform.base_url). Reads are GETs with an `op` query,
writes are POSTs of a JSON body to the same URL:

  GET  ?op=list&all=true                         {"challenges": [{id, name, day, lane, mode, solved}]}
  GET  ?op=status&challenge=<id>                 the attempt: name, prompt, questions[], answer_ids[],
                                                 download/sha256 or artifacts[], targets[], deadline;
                                                 an unstarted id: HTTP 409 {"error": "start_required"}
  GET  ?op=artifact&challenge=<id>&delivery=<i>  the bytes of delivery i (0-based); the file name is
                                                 in Content-Disposition
  POST {"challenge": <id>}                       start the attempt (a timed id starts a clock)
  POST {"challenge": <id>, "answers": {aid: v}}  submit: result CORRECT (with the flag) | accepted
                                                 (banked, `remaining` left) | incorrect | already_solved

Mapping onto PlatformAdapter:
  * A challenge takes one or more answers. submit(cid, value) sends {aid: value} when the attempt
    has exactly one answer id; a multi-answer challenge is addressed "<cid>#<answer id>". "accepted"
    (that answer banked, others remaining) and CORRECT are both SubmitStatus.CORRECT.
  * Known refusals that judge nothing are NOT_ALLOWED: start_required, attempt_expired,
    invalid_answers, invalid_request, payload_too_large; 429 rate_limited is RATE_LIMITED. A word
    no tool knows is a PlatformError naming it: anything that is not CORRECT, accepted, incorrect or
    already_solved is never read as a verdict (the fake Game Master's rule).
  * An unsure answer (a value starting "??", the labels convention) is never sent.
  * submit_answers(cid, {aid: value, ...}) is the batch fast path (B-044): one POST for every answer
    of an attempt, reached only through gate.submit_answers. Every verdict keeps the reply body
    (minus the flag) in SubmitResult.reply, so the Hall of Fame pool fields can be checked
    (ctf/platform/halloffame.py).
  * Instances: start_instance is the attempt start (the web lane's targets come back in it).
    A Time Trial or Mastery id (".../time_trial", ".../mastery") is refused: its start runs a clock,
    and only the opener starts a clock (B-252/B-003). There is no stop op (attempts end at their
    deadline): stop_instance raises NotSupported.
  * The Game Master has no scoreboard op: scoreboard() and challenge_solves() (B-099) raise
    NotSupported.
  * download_files never starts an attempt: an unstarted id raises PlatformError saying so.

Credentials: CTF_TOKEN (legacy HUNTRESS_GM_TOKEN via ctf.env), sent as a Bearer token and never
printed. A loopback base URL (http://127.0.0.1:<port>/, the fake Game Master of a rehearsal) gets
no bearer and the token is never read, as in gm.py.

Not ported (see docs/build-log/B-005.md): the start-body ladder and remembered routes, the delivery
download ladder, the judge.py wire governor/journal, op=retry and op=practice, the release scope fence.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from pathlib import Path
from typing import Any, Mapping

import requests

from .. import env
from ..event import EventProfile
from . import _http
from .base import (Challenge, ChallengeSolve, FileRef, InstanceInfo, NotAllowed, NotSupported,
                   PlatformError, ScoreRow, SubmitResult, SubmitStatus, TeamSolve)

TIMED_SUFFIXES = ("/time_trial", "/mastery")
UNSURE = "??"
DEFAULT_TIMEOUT_S = 30.0
_LOOPBACK = re.compile(r"http://127\.0\.0\.1:\d{1,5}/?")

_REFUSALS = {"start_required", "attempt_expired", "invalid_answers", "invalid_request",
             "payload_too_large", "expired"}


def is_timed(challenge_id: str) -> bool:
    return str(challenge_id).strip().rstrip("/").lower().endswith(TIMED_SUFFIXES)


def is_unsure(value: Any) -> bool:
    if isinstance(value, str):
        return value.lstrip().startswith(UNSURE) or (UNSURE + '{"k":') in value
    return False


def _epoch(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _word(body: Any) -> str | None:
    if isinstance(body, dict):
        w = body.get("error") or body.get("result")
        return w if isinstance(w, str) else None
    return None


def _split(challenge_id: str) -> tuple[str, str | None]:
    cid, sep, aid = str(challenge_id).partition("#")
    if not cid:
        raise PlatformError(f"empty Game Master challenge id in {challenge_id!r}")
    return cid, (aid or None) if sep else None


class GameMasterAdapter:
    kind = "gamemaster"

    def __init__(self, base_url: str, *, token: str | None = None, session: Any = None,
                 timeout_s: float = DEFAULT_TIMEOUT_S):
        if not base_url or not base_url.startswith(("http://", "https://")):
            raise PlatformError(f"Game Master base_url must be http(s), got {base_url!r}")
        self.url = base_url.rstrip("/") + "/"
        self.loopback = bool(_LOOPBACK.fullmatch(self.url))
        self.timeout_s = timeout_s
        if session is None:
            session = requests.Session()
            if self.loopback:
                session.trust_env = False   # no proxy, no ~/.netrc on the way to a rehearsal fake
        self._s = session
        self._s.headers.update({"Accept": "application/json"})
        self._token = token
        if token and not self.loopback:
            self._s.headers["Authorization"] = "Bearer " + token

    # ------------------------------------------------------------------------------- plumbing
    def _send(self, method: str, call: str, *, params: dict | None = None, json: dict | None = None,
              stream: bool = False) -> Any:
        if not self.loopback and not self._token:
            raise PlatformError(f"{call}: no Game Master token; set CTF_TOKEN")
        try:
            r = self._s.request(method, self.url, params=params, json=json, timeout=self.timeout_s,
                                stream=stream)
        except (requests.RequestException, OSError) as e:
            raise PlatformError(f"{call}: {method} failed ({type(e).__name__})") from e
        if r.status_code == 401:
            raise PlatformError(f"{call}: unauthorized; the token is wrong (do not reset it "
                                "automatically; tell the player)")
        return r

    def _get_json(self, call: str, params: dict, ok: tuple[int, ...] = (200,)) -> tuple[int, Any]:
        r = self._send("GET", call, params=params)
        body = _http.json_body(r, call)
        if r.status_code not in ok:
            raise PlatformError(f"{call}: HTTP {r.status_code} {_word(body) or ''}".rstrip())
        return r.status_code, body

    def _rows(self) -> list[dict]:
        _, body = self._get_json("list_challenges", {"op": "list", "all": "true"})
        rows = body.get("challenges") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            raise PlatformError("list_challenges: the answer has no challenges[] list")
        return [r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str)]

    def _status(self, cid: str, call: str) -> tuple[int, dict]:
        code, body = self._get_json(call, {"op": "status", "challenge": cid}, ok=(200, 409))
        if not isinstance(body, dict):
            raise PlatformError(f"{call}: status of {cid} is not a JSON object")
        if code == 409 and _word(body) != "start_required":
            raise PlatformError(f"{call}: status of {cid} -> HTTP 409 {_word(body)}")
        return code, body

    @staticmethod
    def _row_challenge(row: dict) -> Challenge:
        tags = tuple(t for t in (row.get("mode"),
                                 f"day-{row['day']}" if row.get("day") is not None else None) if t)
        return Challenge(id=row["id"], name=str(row.get("name") or row["id"]),
                         category=str(row.get("lane") or ""), solved_by_team=bool(row.get("solved")),
                         tags=tags, raw=row)

    @staticmethod
    def _deliveries(st: dict) -> list[dict]:
        arts = st.get("artifacts")
        if isinstance(arts, list) and arts:
            return [a if isinstance(a, dict) else {} for a in arts]
        if st.get("download") or st.get("sha256"):
            return [{"filename": st.get("filename"), "sha256": st.get("sha256"), "download": st.get("download")}]
        return []

    # ------------------------------------------------------------------------------- reads
    def list_challenges(self) -> list[Challenge]:
        return [self._row_challenge(r) for r in self._rows()]

    def get_challenge(self, challenge_id: str) -> Challenge:
        cid, _ = _split(challenge_id)
        row = next((r for r in self._rows() if r["id"] == cid), None)
        if row is None:
            raise PlatformError(f"get_challenge: {cid} is not on the Game Master's list")
        _, st = self._status(cid, "get_challenge")
        base = self._row_challenge(row)
        files = tuple(FileRef(name=_http.safe_filename(d.get("filename"), f"delivery-{i + 1}"),
                              url=d.get("download")) for i, d in enumerate(self._deliveries(st)))
        targets = [t.get("url") for t in st.get("targets") or () if isinstance(t, dict) and t.get("url")]
        desc = "\n\n".join(x for x in (st.get("prompt"), st.get("guidance")) if isinstance(x, str) and x)
        return Challenge(id=cid, name=str(st.get("name") or base.name), category=base.category,
                         description=desc, files=files, connection_info="\n".join(targets),
                         solved_by_team=base.solved_by_team or st.get("result") == "CORRECT",
                         tags=base.tags, raw={"list": row, "status": st})

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        """Every delivery of the current attempt, sha256-checked. Never starts an attempt."""
        cid, _ = _split(challenge_id)
        code, st = self._status(cid, "download_files")
        if code == 409:
            raise PlatformError(f"download_files: {cid} has no attempt yet (start_required); start it "
                                "first (start_instance; a timed id is started only by the opener)")
        deliveries = self._deliveries(st)
        if not deliveries:
            raise PlatformError(f"download_files: {cid} lists no deliveries ({_word(st) or 'no artifacts'})")
        dest = Path(dest)
        written = []
        for i, d in enumerate(deliveries):
            r = self._send("GET", "download_files", params={"op": "artifact", "challenge": cid, "delivery": i},
                           stream=True)
            try:
                if r.status_code != 200:
                    raise PlatformError(f"download_files: delivery {i} of {cid} -> HTTP {r.status_code}")
                data = b"".join(c for c in r.iter_content(65536) if c)
                name = d.get("filename")
                if not name:
                    m = re.search(r'filename="?([^";]+)"?', (r.headers or {}).get("content-disposition", ""))
                    name = m.group(1) if m else None
                name = _http.safe_filename(name, "artifact.bin")
            finally:
                close = getattr(r, "close", None)
                if close:
                    close()
            want = d.get("sha256")
            got = hashlib.sha256(data).hexdigest()
            if isinstance(want, str) and want and want.lower() != got:
                raise PlatformError(f"download_files: delivery {i} of {cid} sha256 {got} does not match "
                                    f"the Game Master's {want}; nothing written")
            out = dest / name if len(deliveries) == 1 else dest / f"delivery-{i + 1:02d}" / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            written.append(out)
        return written

    def team_solves(self) -> list[TeamSolve]:
        return [TeamSolve(challenge_id=r["id"]) for r in self._rows() if r.get("solved")]

    def scoreboard(self) -> list[ScoreRow]:
        raise NotSupported("the Game Master offers no scoreboard op (its ops: list, status, artifact, "
                           "openapi, start, submit, retry, practice)")

    def challenge_solves(self, challenge_id: str) -> list[ChallengeSolve]:
        raise NotSupported(f"challenge_solves({challenge_id}): the Game Master publishes no other team's "
                           "solves (its ops: list, status, artifact, openapi, start, submit, retry, "
                           "practice); give first-blood times by hand")

    # ------------------------------------------------------------------------------- submit
    def _answer_id(self, cid: str, aid: str | None) -> str:
        if aid:
            return aid
        code, st = self._status(cid, "submit")
        ids = st.get("answer_ids")
        if not isinstance(ids, list) or not ids:
            ids = [q.get("id") for q in st.get("questions") or () if isinstance(q, dict)]
        ids = [i for i in ids if isinstance(i, str) and i]
        if len(ids) != 1:
            raise PlatformError(f"submit: {cid} takes {len(ids)} answers ({', '.join(ids) or 'none listed'}); "
                                f"address one as '{cid}#<answer id>'")
        return ids[0]

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        """The raw POST. Only the SubmitGate calls this."""
        if is_unsure(flag):
            return SubmitResult(SubmitStatus.NOT_ALLOWED, "an unsure answer ('??...') is never sent", sent=False)
        cid, aid = _split(challenge_id)
        aid = self._answer_id(cid, aid)
        return self._post_answers("submit", cid, {aid: flag})

    def submit_answers(self, challenge_id: str, answers: Mapping[str, str]) -> SubmitResult:
        """The raw batch POST (B-044's fast path): every answer of one attempt in ONE request,
        {"challenge": cid, "answers": {aid: value, ...}}. The judge grades the batch as one: CORRECT
        or accepted means every answer in it is right; a bare incorrect says at least one is wrong.
        Only the SubmitGate calls this (gate.submit_answers). An unsure value refuses the whole
        batch before any request."""
        cid, aid = _split(challenge_id)
        if aid is not None:
            raise PlatformError(f"submit_answers: address the challenge ({cid}), not one answer "
                                f"({challenge_id}); the answers map names the answer ids")
        if not isinstance(answers, Mapping) or not answers:
            raise PlatformError(f"submit_answers: {cid}: no answers to send")
        for k, v in answers.items():
            if not isinstance(k, str) or not k or not isinstance(v, str):
                raise PlatformError(f"submit_answers: {cid}: answer ids and values must be non-empty "
                                    f"strings (got {k!r})")
        unsure = sorted(k for k, v in answers.items() if is_unsure(v))
        if unsure:
            return SubmitResult(SubmitStatus.NOT_ALLOWED, f"unsure answer(s) ('??...') for "
                                f"{', '.join(unsure)}: the batch is never sent", sent=False)
        return self._post_answers("submit_answers", cid, dict(answers))

    def _post_answers(self, call: str, cid: str, answers: dict) -> SubmitResult:
        r = self._send("POST", call, json={"challenge": cid, "answers": answers})
        if r.status_code == 429:
            return SubmitResult(SubmitStatus.RATE_LIMITED, "rate_limited", retry_after=_http.retry_after(r))
        body = _http.json_body(r, call)
        word = _word(body)
        reply = {k: v for k, v in body.items() if k != "flag"} if isinstance(body, dict) else None
        if r.status_code == 200 and word == "CORRECT":
            got = body.get("flag")
            return SubmitResult(SubmitStatus.CORRECT, f"CORRECT; flag: {got}" if got else "CORRECT",
                                reply=reply)
        if r.status_code == 200 and word == "accepted":
            return SubmitResult(SubmitStatus.CORRECT, f"accepted; {body.get('remaining')} answer(s) remaining",
                                reply=reply)
        if r.status_code == 200 and word == "incorrect":
            return SubmitResult(SubmitStatus.INCORRECT, "incorrect", reply=reply)
        if r.status_code == 200 and word == "already_solved":
            return SubmitResult(SubmitStatus.ALREADY_SOLVED, str(body.get("message") or "already_solved"),
                                reply=reply)
        if word in _REFUSALS:
            return SubmitResult(SubmitStatus.NOT_ALLOWED, f"HTTP {r.status_code} {word}", reply=reply)
        raise PlatformError(f"{call}: {cid} answered HTTP {r.status_code} {word or '(no word)'}; not a "
                            "Game Master verdict (read the contract: op=openapi)")

    # ------------------------------------------------------------------------------- instances
    def _instance(self, cid: str, code: int, body: dict) -> InstanceInfo:
        word = _word(body)
        if code == 409 and word == "start_required":
            return InstanceInfo(cid, "stopped")
        if word == "expired":
            return InstanceInfo(cid, "stopped")
        if word == "preparing":
            return InstanceInfo(cid, "starting")
        if body.get("attempt_id") or body.get("questions") or word == "CORRECT":
            targets = [t.get("url") for t in body.get("targets") or () if isinstance(t, dict) and t.get("url")]
            return InstanceInfo(cid, "running", "\n".join(targets), _epoch(body.get("deadline")))
        return InstanceInfo(cid, "unknown")

    def start_instance(self, challenge_id: str) -> InstanceInfo:
        cid, _ = _split(challenge_id)
        if is_timed(cid):
            raise NotAllowed(f"start_instance: {cid} is a timed id; its start runs a clock, and only the "
                             "opener starts a clock")
        r = self._send("POST", "start_instance", json={"challenge": cid})
        if r.status_code == 429:
            raise PlatformError(f"start_instance: {cid} rate_limited; retry after "
                                f"{_http.retry_after(r) or 'a pause'}")
        body = _http.json_body(r, "start_instance")
        if r.status_code != 200:
            raise PlatformError(f"start_instance: {cid} -> HTTP {r.status_code} {_word(body) or ''}".rstrip())
        return self._instance(cid, 200, body if isinstance(body, dict) else {})

    def instance_status(self, challenge_id: str) -> InstanceInfo:
        cid, _ = _split(challenge_id)
        code, body = self._status(cid, "instance_status")
        return self._instance(cid, code, body)

    def stop_instance(self, challenge_id: str) -> InstanceInfo:
        raise NotSupported("the Game Master has no stop op; an attempt ends at its deadline")


def make_adapter(profile: EventProfile, *, session: Any = None,
                 environ: Mapping[str, str] | None = None, **kw) -> GameMasterAdapter:
    if profile.platform.kind != "gamemaster":
        raise PlatformError(f"gamemaster adapter asked for a {profile.platform.kind!r} event")
    if profile.rules.ai_on_platform == "forbidden":
        raise NotAllowed(f"event {profile.slug!r} forbids automation on the platform; use manual mode")
    base_url = profile.platform.base_url or ""
    override = env.get("CTF_PLATFORM_URL", environ=environ)
    if override and override.rstrip("/") != base_url.rstrip("/"):
        raise PlatformError("CTF_PLATFORM_URL is set and differs from the event profile's "
                            f"platform.base_url ({base_url}); the profile is the one source, so edit it "
                            "(or unset CTF_PLATFORM_URL)")
    loopback = bool(_LOOPBACK.fullmatch(base_url.rstrip("/") + "/"))
    token = None
    if not loopback:
        raw = env.get("CTF_TOKEN", environ=environ)
        token = _http.check_secret(raw, "CTF_TOKEN") if raw else None
    return GameMasterAdapter(base_url, token=token, session=session, **kw)
