"""No-model timed-start routing (B-231): a refused timed start reads op=openapi and retries once.

Huntress Day 8: three lanes (mobile, metadata, script) each spent about 60 s repeating a refused
default timed-start body ({"challenge": id}, answered 409 training_rotation_invalid) until an agent
read the contract, added run_for_time:true to the runner and resumed the lane. The contract already
listed the property. This module is the path that needs no agent:

    starter = timedstart.TimedStarter(gate)            # the clock-start seam of latency.open_timed
    info = starter("mobile-day-08/time_trial")         # -> InstanceInfo; starter.results[cid] says how

  1. POST the start body (the body remembered for this event, else the default {"challenge": id})
     through latency.StartGuard: the start record in <workdir>/wire/starts.json keeps every process
     of the event from POSTing a second clock start while one is posting, preparing or unknown.
  2. A refusal that a different body could cure (an HTTP 4xx with a word that is not one of
     NOT_BODY_WORDS: rate_limited, already_solved, ...) reads op=openapi ONCE (a GET through the
     adapter's wired session, so the wire journals it as op "openapi"), and start_body_from_openapi
     derives the start body the document lists: every POST JSON schema that names `challenge` and
     does not require `answers`; run_for_time:true when it lists run_for_time; every other required
     property from its const, single enum value or default. A required property with no determinable
     value, a document that lists no start schema, or a derived body equal to the refused one is a
     TimedStartError naming why (no guess, and never the refused body again).
  3. The derived body is POSTed once more through StartGuard. A second refusal is final
     (TimedStartError with both words); there is no third POST.
  4. A start that returned an attempt is checked with ctf/platform/halloffame.py
     (TimedAttempt.from_reply: classifies whose attempt it is, reads the pool fields, writes the
     hof.start ledger record). A regular attempt on a timed id (run_for_time or hall_of_fame_eligible
     false) prints the halloffame NOTE line: it scores but posts nothing to the fastest-times board.
  5. A derived body that returned an attempt is remembered in <workdir>/wire/start_body.json
     (without the challenge id), so every other lane of the event sends it first and never pays the
     refusal or the openapi read (the spec's "shared across lanes").

Only the opener starts a clock: TimedStarter is the default `starter` of latency.open_timed and
latency.ladder_on_green (B-252), and the adapter's start_instance still refuses timed ids. An untimed
id is refused here before any request. A POST whose outcome is unknown (it raised: a timeout; or a 5xx
or other non-4xx reply, which a gateway can send after the attempt was created) is never retried with
another body and never reads op=openapi: StartGuard resolves it by status only.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from . import _http
from . import halloffame as _hof
from . import latency as _lat
from .base import InstanceInfo, NotAllowed, PlatformError
from .gamemaster import is_timed

BODY_NAME = "start_body.json"
START_CALL = "start_timed"          # the call name a timed-start POST is reported under
RUN_FOR_TIME = "run_for_time"
_NEVER_FILLED = frozenset({"challenge", "answers", "op", RUN_FOR_TIME})
# Refusals another body cannot cure: the attempt state, the rate limit, the credential, an unknown id.
NOT_BODY_WORDS = frozenset({
    "rate_limited", "already_solved", "attempt_active", "attempt_expired", "expired",
    "base_not_solved", "retry_not_available", "unknown_challenge", "challenge_unavailable",
    "unauthorized", "start_required", "CORRECT"})
_REF_DEPTH = 8
_ALT_DEPTH = 4


class TimedStartError(PlatformError):
    """The timed start could not be routed: the refusal, the contract, or the retry, named."""


class TimedStartRefused(NotAllowed):
    """The Game Master refused a timed-start POST with a word: nothing was created. A NotAllowed, so
    StartGuard drops the start record it wrote for the POST (a refused start is not pending)."""

    def __init__(self, challenge: str, status: int, word: str, body: Mapping | None = None,
                 retry_after: float | None = None):
        self.challenge, self.status, self.word = challenge, status, word
        self.reply = {k: v for k, v in (body or {}).items() if k != "flag"}
        self.retry_after = retry_after
        super().__init__(f"timed start of {challenge} refused: HTTP {status} {word}")


# ------------------------------------------------------------------------------------- the contract

def _resolve(doc: Any, node: Any) -> Any:
    """A local $ref ('#/components/schemas/X') followed, at most _REF_DEPTH deep."""
    depth = 0
    while (isinstance(node, dict) and isinstance(node.get("$ref"), str)
           and node["$ref"].startswith("#/") and depth < _REF_DEPTH):
        cur = doc
        for part in node["$ref"][2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(cur, dict) else None
        node, depth = cur, depth + 1
    return node


def _objects(doc: Any, schema: Any, depth: int = 0) -> list[dict]:
    """The object schemas a request schema may be: oneOf/anyOf alternatives, allOf merged."""
    schema = _resolve(doc, schema)
    if not isinstance(schema, dict) or depth > _ALT_DEPTH:
        return []
    alts = schema.get("oneOf") or schema.get("anyOf")
    if isinstance(alts, list) and alts:
        return [m for a in alts for m in _objects(doc, a, depth + 1)]
    out = {k: v for k, v in schema.items() if k != "allOf"}
    for part in schema.get("allOf") or []:
        for m in _objects(doc, part, depth + 1)[:1]:
            out["properties"] = {**(m.get("properties") or {}), **(out.get("properties") or {})}
            out["required"] = list(dict.fromkeys(list(out.get("required") or []) + list(m.get("required") or [])))
    return [out]


def start_schemas(doc: Any) -> list[dict]:
    """Every JSON request schema of a POST in an op=openapi document that names `challenge` and does
    not require `answers` (a submit): the bodies a start may carry."""
    if not isinstance(doc, dict):
        raise TimedStartError(f"op=openapi did not answer a JSON object (got {type(doc).__name__})")
    found: list[dict] = []
    paths = doc.get("paths")
    for item in (paths.values() if isinstance(paths, dict) else ()):
        post = item.get("post") if isinstance(item, dict) else None
        if not isinstance(post, dict):
            continue
        content = (_resolve(doc, post.get("requestBody")) or {}).get("content")
        for ctype, media in (content.items() if isinstance(content, dict) else ()):
            if "json" in str(ctype) and isinstance(media, dict):
                found += _objects(doc, media.get("schema"))
    return [s for s in found if isinstance(s.get("properties"), dict) and "challenge" in s["properties"]
            and "answers" not in (s.get("required") or [])]


def _value(schema: Any) -> tuple[bool, Any]:
    """(True, value) when a property's schema names exactly one value to send: const, a one-value
    enum, or a default. (False, None) otherwise."""
    if not isinstance(schema, dict):
        return False, None
    if "const" in schema:
        return True, schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and len(enum) == 1:
        return True, enum[0]
    if "default" in schema:
        return True, schema["default"]
    return False, None


def _asks_for_time(schema: Any) -> bool:
    """Whether run_for_time's schema allows true (a boolean, or a const/enum naming true)."""
    if not isinstance(schema, dict):
        return False
    if "const" in schema:
        return schema["const"] is True
    enum = schema.get("enum")
    if isinstance(enum, list):
        return any(v is True for v in enum)
    return schema.get("type") in ("boolean", None)


def start_body_from_openapi(doc: Any, challenge: str) -> dict:
    """The timed-start body an op=openapi document lists for `challenge`: {"challenge": id}, plus
    run_for_time:true when a start schema lists run_for_time, plus every other required property
    from its const, one-value enum or default. Raises TimedStartError when the document lists no
    start schema or a required property whose value it does not name."""
    schemas = start_schemas(doc)
    if not schemas:
        raise TimedStartError("op=openapi lists no start body (no POST JSON schema naming `challenge` "
                              "that is not a submit)")
    body: dict = {"challenge": challenge}
    props: dict = {}
    required: list[str] = []
    for s in schemas:
        for name, sch in s["properties"].items():
            props.setdefault(str(name), _resolve(doc, sch) if isinstance(sch, dict) else {})
        required += [r for r in (s.get("required") or []) if isinstance(r, str) and r not in required]
    if RUN_FOR_TIME in props and _asks_for_time(props[RUN_FOR_TIME]):
        body[RUN_FOR_TIME] = True
    unknown = []
    for name in required:
        if name in _NEVER_FILLED:
            continue
        ok, v = _value(props.get(name))
        if ok:
            body[name] = v
        else:
            unknown.append(name)
    if unknown:
        raise TimedStartError(f"op=openapi requires {', '.join(unknown)} on a start and names no single "
                              "value for it (no const, one-value enum or default); not guessed")
    return body


# ------------------------------------------------------------------------------------- the memory

def body_path(workdir: Path) -> Path:
    return Path(workdir) / _lat._wire.DIR_NAME / BODY_NAME


def remembered_body(workdir: Path) -> dict | None:
    """The start-body template (no challenge id) a derived start of this event got an attempt with,
    or None. A file that does not parse raises TimedStartError (never read as 'nothing remembered':
    that would send the refused default again)."""
    p = body_path(workdir)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise TimedStartError(f"remembered start body {p} does not parse ({e}); fix or remove it "
                              "(timedstart.forget_body)") from e
    tmpl = data.get("body") if isinstance(data, dict) else None
    if not isinstance(tmpl, dict) or "challenge" in tmpl:
        raise TimedStartError(f"remembered start body {p} has no body template object; fix or remove it "
                              "(timedstart.forget_body)")
    return tmpl


def remember_body(workdir: Path, body: Mapping, *, learned_from: str, refused: str,
                  now: float | None = None) -> Path:
    """Remember a start body (its challenge id dropped) for every lane of the event."""
    p = body_path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmpl = {k: v for k, v in body.items() if k != "challenge"}
    rec = {"body": tmpl, "learned_from": learned_from, "refused": refused,
           "at": time.time() if now is None else now}
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, sort_keys=True, indent=1)
    os.replace(tmp, p)
    return p


def forget_body(workdir: Path) -> bool:
    """Drop the remembered start body. True when there was one."""
    try:
        body_path(workdir).unlink()
        return True
    except FileNotFoundError:
        return False


# ------------------------------------------------------------------------------------- the router

@dataclass
class StartRoute:
    """How one timed start went. bodies: every body POSTed, in order. refused: the refusal words, in
    order. openapi: whether op=openapi was read. attempt: the halloffame.TimedAttempt of the reply
    that returned an attempt (None when the start resolved by status only)."""
    challenge: str
    bodies: list[dict] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    openapi: bool = False
    learned: bool = False
    outcome: _lat.StartOutcome | None = None
    attempt: _hof.TimedAttempt | None = None

    @property
    def eligibility(self) -> _hof.Eligibility | None:
        return self.attempt.eligibility if self.attempt is not None else None


class TimedStarter:
    """The no-model timed-start path (see the module docstring); callable(cid) -> InstanceInfo, the
    `starter` seam of latency.open_timed / ladder_on_green."""

    def __init__(self, gate: Any, *, workdir: Path | None = None, guard: _lat.StartGuard | None = None,
                 err: Any = None):
        adapter = _lat._adapter(gate)
        if getattr(adapter, "kind", None) != "gamemaster":
            raise NotAllowed(f"timed starts are a Game Master route; the {getattr(adapter, 'kind', '?')} "
                             "adapter has no timed ids")
        self.gate, self.adapter = gate, adapter
        self.workdir = Path(workdir) if workdir is not None else _lat.workdir_of(gate)
        self.guard = guard if guard is not None else _lat.StartGuard(gate, workdir=self.workdir, err=err)
        self._err = err
        self.results: dict[str, StartRoute] = {}

    @property
    def err(self):
        return self._err if self._err is not None else sys.stderr

    # ------------------------------------------------------------------------------ wire calls
    def _poster(self, route: StartRoute, body: dict) -> Callable[[str], InstanceInfo]:
        def post(cid: str) -> InstanceInfo:
            route.bodies.append(dict(body))
            r = self.adapter._send("POST", START_CALL, json=body)
            if r.status_code == 429:
                raise TimedStartRefused(cid, 429, "rate_limited", retry_after=_http.retry_after(r))
            reply = _http.json_body(r, START_CALL)
            word = reply.get("error") or reply.get("result") if isinstance(reply, dict) else None
            if r.status_code != 200:
                # Only a 4xx with a word is a definite refusal (nothing was created). A 5xx (or any
                # other non-200) can come from a gateway after the attempt was already created: its
                # outcome is unknown, and StartGuard resolves it by status, never by another POST.
                if 400 <= r.status_code < 500 and isinstance(word, str) and word:
                    raise TimedStartRefused(cid, r.status_code, word, reply if isinstance(reply, dict) else None)
                raise PlatformError(f"{START_CALL}: {cid} -> HTTP {r.status_code}"
                                    f"{' ' + word if isinstance(word, str) and word else ' with no word'}; "
                                    "not a definite refusal, the outcome is unknown")
            if not isinstance(reply, dict):
                raise PlatformError(f"{START_CALL}: {cid} answered HTTP 200 with a non-object body")
            date = (getattr(r, "headers", None) or {}).get("Date")
            elapsed = getattr(r, "elapsed", None)
            route.attempt = _hof.TimedAttempt.from_reply(
                self.gate, cid, reply, date=date,
                elapsed_s=max(0.0, elapsed.total_seconds()) if elapsed is not None else 0.0,
                workdir=self.workdir)
            return self.adapter._instance(cid, 200, reply)
        return post

    def read_openapi(self) -> Any:
        """GET op=openapi once through the adapter's wired session (journaled as op "openapi")."""
        r = self.adapter._send("GET", "openapi", params={"op": "openapi"})
        doc = _http.json_body(r, "openapi")
        if r.status_code != 200:
            word = doc.get("error") if isinstance(doc, dict) else None
            raise TimedStartError(f"op=openapi -> HTTP {r.status_code} {word or ''}".rstrip())
        return doc

    def _start(self, route: StartRoute, cid: str, body: dict) -> _lat.StartOutcome:
        out = self.guard.start(cid, post=self._poster(route, body))
        route.outcome = out
        return out

    # ------------------------------------------------------------------------------ the route
    def __call__(self, challenge: str) -> InstanceInfo:
        return self.start(challenge)

    def start(self, challenge: str) -> InstanceInfo:
        cid = _lat._key(challenge)
        if not is_timed(cid):
            raise NotAllowed(f"timedstart: {cid} is not a timed id (.../time_trial, .../mastery); an "
                             "untimed start goes through StartGuard / open_release")
        route = StartRoute(cid)
        self.results[cid] = route
        tmpl = remembered_body(self.workdir)
        first = {"challenge": cid, **(tmpl or {})}
        try:
            out = self._start(route, cid, first)
        except TimedStartRefused as e:
            route.refused.append(e.word)
            if e.word in NOT_BODY_WORDS:
                raise TimedStartError(f"timed start of {cid} refused with {e.word} (HTTP {e.status}): "
                                      "another body cannot cure it; op=openapi not read, no retry") from e
            out = self._reroute(route, cid, first, e)
        return self._info(route, cid, out)

    def _reroute(self, route: StartRoute, cid: str, refused: dict, why: TimedStartRefused) -> _lat.StartOutcome:
        route.openapi = True
        doc = self.read_openapi()
        try:
            body = start_body_from_openapi(doc, cid)
        except TimedStartError as e:
            raise TimedStartError(f"timed start of {cid} refused with {why.word}; {e}; no retry") from why
        if body == refused:
            raise TimedStartError(f"timed start of {cid} refused with {why.word}, and op=openapi lists no "
                                  f"other start body than the refused one ({sorted(refused)}); no retry")
        print(f"ctf timedstart: {cid}: start refused with {why.word}; op=openapi lists "
              f"{json.dumps({k: v for k, v in body.items() if k != 'challenge'}, sort_keys=True)}: "
              "retrying once with it", file=self.err)
        try:
            out = self._start(route, cid, body)
        except TimedStartRefused as e:
            route.refused.append(e.word)
            raise TimedStartError(f"timed start of {cid} refused twice: {why.word} with the first body, "
                                  f"{e.word} with the op=openapi body; no third start") from e
        if route.attempt is not None:
            remember_body(self.workdir, body, learned_from=cid, refused=why.word)
            route.learned = True
        return out

    def _info(self, route: StartRoute, cid: str, out: _lat.StartOutcome) -> InstanceInfo:
        if route.attempt is not None:
            note = route.attempt.eligibility.note
            if note:
                print(f"ctf timedstart: NOTE: {note}", file=self.err)
        if out.state == "unknown" or out.info is None:
            raise TimedStartError(f"timed start of {cid}: outcome unknown ({out.note or 'no status'}); "
                                  "resolved by status only, no other body sent. Read `ctf latency pending`")
        return out.info


def router(gate: Any, *, workdir: Path | None = None, err: Any = None) -> TimedStarter:
    """The default clock-start seam of latency.open_timed / ladder_on_green."""
    return TimedStarter(gate, workdir=workdir, err=err)
