#!/usr/bin/env python3
"""web_patch: a web live-fix hook (backlog row 505; branch wave15/web-patch-hook).

The GET recipe mechanism remains agent-invoked: the shipped proof hunter does not
call it automatically.  Layer 1 does import this module for the separate row-513
auto-POST bridge, which is gated by the player's ``webpost`` switch and keeps its
own narrow contracts.  An agent proves a NEW web class on the base by hand; this
module lets the SAME GET recipe recover each further target's own proof -- the Time
Trial variant, the Mastery sub-targets, any later target -- so `tools/verify.py` can
bank it. It is the web sibling of a lane's `day_patch.py`: a new file an agent writes
for a class the shipped readers do not cover, loaded by name, never an edit to a
shipped solver.

What it is for. proof_hunt (solvers/web/proof_hunt.py) is already variant-proof for the
classes it knows -- it re-derives routes, clues and pages on every target, so it banks
a Mastery's sub-targets by itself. web_patch is for the class proof_hunt does NOT know:
an agent works out the recipe on the base, writes it here as data (GET-only, variant-
proof), and web_patch replays it against every other target and recovers the self-proven
proof. A recipe hard-codes no per-variant hex: a step's path is a template whose
placeholders are filled from THIS target's /api/clues feed and from fields captured out
of earlier steps' JSON, exactly as the agent read them on the base.

THE BRIGHT LINE (never-wrong, same as every solver and day_patch):
  * A proof is banked ONLY when the target SELF-PROVES it: the designated payoff step's
    response is JSON that AFFIRMS success (a truthy `ok`/`success`, or `status` == ok/
    success) AND carries exactly one proof-like value, of the stable wire form -- `proof_` +
    32 lowercase hex. UUID-v4 nibbles remain an empirical validator, not a contract. We do
    not assert the proof; the target does.
  * The one-proof rule: a proof seen on more than one value, or seen on a PLAIN (non-
    payoff) step too (the site shows it anyway -- a decoy), turns the answer to None.
  * A CourseStack-style flag (`word{...}`, or a bare value a payoff labels as a flag) is
    ALWAYS None and is SURFACED for the player (`COURSESTACK FLAG <challenge>: <flag>`);
    it is NEVER an answer and NEVER auto-submitted. Only an exact lowercase `proof_<32hex>`
    wire value is ever banked. A labelled different-shape value on affirmed success is
    surfaced as a bounded candidate and also stays None.

SAFETY (unchanged from proof_hunt and web.WebClient):
  * GET only. A step with any other method is refused and its target is None (writes --
    POST, PUT, DELETE, ... -- are backlog row 513, the player's).
  * The destructive guard (proof_hunt.is_destructive): a resolved request path or a
    query parameter NAME whose words change or end state (delete, reset, logout, drop,
    update, upload, exec, run, ...; the FHS directory name `run` exempt) is refused.
  * Same-host scope: every request goes through solvers/toolkits/web.py WebClient, which
    is hard-locked to the attempt's own scheme+host+port and refuses the Game Master.
    Redirects are never followed (allow_redirects=False); a recipe adds a step for a hop.
  * Request budget and deadline: every request counts against ctx["max_requests"] and is
    refused within ctx-deadline's pad; a Mastery's targets run in parallel behind one
    shared stop flag, so nothing is sent after solve_targets returns.
  * We NEVER execute, import, eval or deserialize anything a target returns. Responses are
    read as text/JSON and scanned with regexes only.

CONTRACT (mirrors proof_hunt's, with the recipe as the first argument):

    solve_targets(recipe, targets, ctx) -> {answer_id: "proof_<32 hex>" | None}
    recover(recipe, targets, ctx)       -> {"answers": {aid: proof}, "flags": [...], "targets": {aid: summary}}
    apply_recipe(recipe, url, ctx)      -> one target's Outcome dict

    targets = [{"answer_id": "proof-1", "url": "https://<host>/", "index": 1, "question": "<text>"}, ...]
    ctx     = {"deadline": <epoch s | None>, "max_requests": <int, shared by the whole target set>,
               "log_dir": <path | None>,
               "challenge": <id>, "client_factory": <callable(url, timeout) -> client | None (tests)>}

A RECIPE (plain data, what the agent writes for the new class):

    {
      "name": "session-fixation",                 # a label, for the log only
      "clues": true,                               # fetch /api/clues and bind its string fields as {clue.<field>}
      "steps": [
        {"get": "{clue.feature_route}?sid={clue.session_hint}",      # plant the session (Set-Cookie kept by the jar)
         "capture": {"status_route": "status_url"}},                # read a field out of this step's JSON
        {"get": "{clue.secondary_route}", "payoff": true}           # the proof comes back here, self-proven
      ]
    }

  * A step's `get` is a path template. `{name}` is replaced from the context: clue fields
    (`clue.<field>`, when `clues` is true) and vars captured by earlier steps. A template
    that names a var no step provided fails the target (None, `stopped` says which).
  * `capture` binds {var: selector} from the step's JSON response; a selector is a dotted
    path (`data.route`, `items.0.href`) or a bare top-level key.
  * `payoff: true` marks the self-prove step(s). A recipe with no payoff step treats its
    last step as the payoff. Exactly the payoff steps may bank a proof; every other step
    is a plain page, so a proof it shows is a decoy.
  * `headers`: an optional {name: value-template} of request headers (a browser's
    Sec-Fetch-*/Referer for the day-06 callback class); header names/values pass the same
    destructive guard, and the Authorization/Cookie a forged token needs are allowed.

CLI (prints the answers and the exact verify.py command; submits NOTHING unless --bank):

    web_patch.py <recipe.json> <challenge id> [--seconds N] [--max-requests N]
                 [--target <answer id>=<url> ...] [--bank]

reads the recipe, reads <challenges>/day-NN/<challenge id>/start.json for its targets
(or takes --target), prints {answer_id: proof|None}, the surfaced flags and the command
`tools/verify.py <id> --answers FILE`; with --bank it runs that command for the base id.
Exit 0 when a proof was recovered, 2 when none, 1 on a usage or file problem.
"""
import argparse
import concurrent.futures as cf  # noqa: F401  (kept for parity; targets use threads like proof_hunt)
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths as ctf_paths, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import paths as ctf_paths, flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
_TOOLS = HERE.parent.parent / "tools"   # row 513: for `switches` (the webpost gate) and the by-hand post bridge
for _p in (HERE, _TK, _TOOLS):          # solvers/web (proof_hunt), solvers/toolkits (web), tools (switches)
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# Single source of truth for the auto-submit proof form, the SEEN scanner and the destructive
# guard: proof_hunt owns them, so web_patch can never drift from the shipped reader.
import proof_hunt as _ph  # noqa: E402  (solvers/web/proof_hunt.py)
import web as _web        # noqa: E402  (solvers/toolkits/web.py: the scope-locked WebClient)
import security_json as _security_json  # noqa: E402 -- fail-closed target JSON
try:
    import forge_event as _response_policy  # noqa: E402 -- carriers/baseline integrity
except Exception:  # pragma: no cover - partial exports fail closed below
    _response_policy = None

# Row 513 (the auto-POST bridge). post_exploit is REQUIRED for the bridge to act; a missing/broken import is
# fail-safe (the bridge then no-ops and Layer 1 is exactly today's GET-only behaviour). The GET-only recipe
# hook above needs neither. The webpost gate was the player's switch in tools/switches.py, which the merge
# plan archived ("replaced by event profile keys"); B-001b removed that import, which could never load, so
# the bridge stays OFF (WEBPOST_GATE says why) until an event-profile key replaces the switch.
try:
    import post_exploit as _pe  # noqa: E402  (solvers/web/post_exploit.py; the never-wrong NON-DESTRUCTIVE POSTer)
except Exception:               # pragma: no cover - import guard; the bridge then no-ops
    _pe = None
WEBPOST_GATE = ("off: the webpost switch lived in tools/switches.py (Huntress Layer 1), archived by the "
                "merge plan; no event-profile key replaces it yet")

PROOF_SEEN = _ph.PROOF_SEEN            # proof_ + 32 hex, any case (a decoy counts as SEEN)
is_proof = _ph.is_proof                # lowercase proof_32hex; UUID-v4 is an empirical validator only
is_destructive = _ph.is_destructive
scan_for_proofs = _ph.scan_for_proofs

# A CourseStack-style flag: `word{...}`. Never banked; surfaced for the player.
FLAG_RE = flagfmt.SHAPE_TEXT  # any-prefix shape (ctf.flagfmt.shape): broad seen/decoy scan, never returned
# Words a payoff may use to LABEL a bare value as the CourseStack flag, so we never bank it.
_FLAG_LABEL = re.compile(r"(?i)\b(?:flag|coursestack|course_stack|ctf_flag|submission)\b")
# A future proof format is evidence, never an answer.  Collect it only from a
# payoff response which itself affirms success, and keep the scan bounded.
_CANDIDATE_LABEL = re.compile(
    r"(?i)(?:^|[_-])(?:proof|evidence|flag|objective|answer|submission)(?:$|[_-])")
_LABELLED_VALUE = re.compile(
    r"(?i)\b(?:proof|evidence|flag|objective|answer|submission)\b\s*[:=]\s*"
    r"(?:[\"']([^\"'\r\n]{3,256})[\"']|([A-Za-z0-9_.:{}@/+=-]{3,256}))")
_PROOF_LIKE = flagfmt.PROOF_ANYCASE
MAX_CANDIDATES = 12
MAX_CANDIDATE_TEXT = 400_000

REQUEST_TIMEOUT = 8.0
DEADLINE_PAD = 0.3
MAX_STEPS = 24                         # a recipe's steps, a hard cap so a bad recipe cannot loop
WORKERS = 6
_VAR = re.compile(r"\{([A-Za-z0-9_.]+)\}")


# -- helpers --------------------------------------------------------------------------------------------
def _json_of(text):
    """Parse a text body as JSON, or None. Never raises."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    if not t or t[0] not in "{[":
        return None
    try:
        return _security_json.loads(t, max_chars=MAX_CANDIDATE_TEXT)
    except Exception:
        return None


def _select(doc, selector):
    """A dotted path into a parsed JSON doc (keys and numeric indices), or None. `cur.key.0.x`."""
    if doc is None or not isinstance(selector, str) or not selector:
        return None
    cur = doc
    for part in selector.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.lstrip("-").isdigit() and -len(cur) <= int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _affirms(doc):
    """True when a JSON payoff AFFIRMS success -- the target self-proving. `ok`/`success` truthy, or
    `status` one of ok/success/true/pass. A non-JSON or unaffirmed body is NOT self-proven."""
    if not isinstance(doc, dict):
        return False
    for k in ("ok", "success", "proven", "solved"):
        v = doc.get(k)
        if v is True or (isinstance(v, (int, float)) and v == 1) or (isinstance(v, str) and v.strip().lower()
                                                                     in ("true", "ok", "yes", "1", "success")):
            return True
    s = doc.get("status")
    if isinstance(s, bool) and s:
        return True
    if isinstance(s, str) and s.strip().lower() in ("ok", "success", "pass", "passed", "solved", "proven"):
        return True
    return False


def _rejects(doc):
    """An explicit JSON rejection.  It dominates an affirmative field in the same response."""
    if not isinstance(doc, (dict, list)):
        return False
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, list):
            stack.extend(v for v in reversed(cur) if isinstance(v, (dict, list)))
            continue
        for key, value in cur.items():
            if isinstance(value, (dict, list)):
                stack.append(value)
            name = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
            if name == "error" and value not in (None, "", False, 0):
                return True
            if name in ("ok", "success", "accepted", "trusted", "authorized", "proven", "solved") \
                    and not (value is True or value == 1 or
                             (isinstance(value, str) and value.strip().lower() in
                              ("true", "yes", "ok", "success", "accepted", "trusted", "authorized", "solved"))):
                return True
            if name in ("status", "result", "effect", "outcome", "message") and isinstance(value, str):
                word = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
                if (word in ("reject", "rejected", "denied", "forbidden", "invalid", "missing", "required",
                             "unauthorized", "not_permitted", "failed", "failure", "error")
                        or word.endswith(("_rejected", "_denied", "_forbidden", "_invalid", "_failed"))):
                    return True
    return False


def _response_affirms(status, doc):
    """True only when this exact payoff response is 2xx and target-authored JSON affirms success."""
    return isinstance(status, int) and 200 <= status < 300 and not _rejects(doc) and _affirms(doc)


def _candidate_walk(obj, path=(), depth=0):
    stack = []
    if isinstance(obj, dict):
        stack.extend((path + (str(key),), value)
                     for key, value in reversed(list(obj.items())))
    elif isinstance(obj, list):
        stack.extend((path + (str(index),), value)
                     for index, value in reversed(list(enumerate(obj))))
    while stack:
        here, value = stack.pop()
        yield here, value
        if isinstance(value, dict):
            stack.extend((here + (str(key),), child)
                         for key, child in reversed(list(value.items())))
        elif isinstance(value, list):
            stack.extend((here + (str(index),), child)
                         for index, child in reversed(list(enumerate(value))))


def _candidate_values(text, doc=None, _integrity=None):
    """Bounded labelled/proof-like values in response data; evidence only, never an answer."""
    text = str(text or "")[:MAX_CANDIDATE_TEXT]
    doc = doc if isinstance(doc, (dict, list)) else _json_of(text)
    out = []

    def add(value):
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return
        value = str(value).strip()
        if not 3 <= len(value) <= 256 or value.lower() in {"null", "none", "true", "false", "ok", "success"}:
            return
        if FLAG_RE.fullmatch(value):       # the existing CourseStack-flag channel surfaces this separately
            return
        if value not in out:
            if len(out) >= MAX_CANDIDATES:
                if isinstance(_integrity, dict):
                    _integrity["incomplete"] = True
                return
            out.append(value)

    if isinstance(doc, (dict, list)):
        for path, value in _candidate_walk(doc):
            if path and _CANDIDATE_LABEL.search(str(path[-1])):
                add(value)
    for match in _PROOF_LIKE.finditer(text):
        add(match.group(0))
    for match in _LABELLED_VALUE.finditer(text):
        add(match.group(1) or match.group(2))
    return out


def _flags(text):
    """Every CourseStack-style flag in a text (`word{...}`), de-duplicated in first-seen order. A
    CSS-shaped match (`btn{color:red}`) is not a flag and is never reported (R-16)."""
    out, seen = [], set()
    for m in FLAG_RE.finditer(str(text or "")):
        v = m.group(0)
        if not flagfmt.shape_reportable(v):
            continue
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _resolve(template, context):
    """Fill {name} in a template from `context`. Returns (resolved, missing_var). A value with a space,
    a control char or a newline is treated as missing (a recipe never builds a request from one)."""
    if not isinstance(template, str):
        return None, "<not a string>"
    missing = [None]

    def sub(m):
        name = m.group(1)
        if name not in context:
            missing[0] = missing[0] or name
            return ""
        v = context[name]
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            missing[0] = missing[0] or name
            return ""
        s = str(v)
        if any(c in s for c in " \t\r\n\x00") or any(ord(c) < 0x20 for c in s):
            missing[0] = missing[0] or name
            return ""
        return s

    out = _VAR.sub(sub, template)
    return (None, missing[0]) if missing[0] else (out, None)


# -- shared wire gate and one target --------------------------------------------------------------------
class _RequestCoordinator:
    """One atomic request budget/deadline/stop gate for a whole target set.

    Reservations are counted before transport starts and remain active until
    it returns.  Closing the coordinator therefore both prevents a late send
    and drains anything which already crossed the reservation boundary.
    """

    def __init__(self, max_requests=60, *, deadline=None, stop=None):
        try:
            self.max_requests = max(0, int(max_requests))
        except (TypeError, ValueError, OverflowError):
            self.max_requests = 60
        try:
            self.deadline = float(deadline) if deadline is not None else None
        except (TypeError, ValueError, OverflowError):
            self.deadline = None
        self.stop = stop if all(hasattr(stop, name) for name in ("is_set", "set")) \
            else threading.Event()
        self._condition = threading.Condition()
        self.closed = False
        self.active_sends = 0
        self.sent = 0

    def _reason_locked(self, *, include_budget=True):
        if self.closed or self.stop.is_set():
            return "shared request coordinator stopped"
        if self.deadline is not None and time.time() >= self.deadline - DEADLINE_PAD:
            return "shared request deadline reached"
        if include_budget and self.sent >= self.max_requests:
            return f"shared request budget of {self.max_requests} spent"
        return None

    def reason(self, *, include_budget=True):
        with self._condition:
            return self._reason_locked(include_budget=include_budget)

    def available(self):
        return self.reason() is None

    def result_allowed(self):
        # The response from the request which consumed the final slot is valid;
        # only stop/deadline close the result side of the gate.
        return self.reason(include_budget=False) is None

    def reserve(self):
        with self._condition:
            reason = self._reason_locked()
            if reason is not None:
                return reason
            self.sent += 1
            self.active_sends += 1
            return None

    def cap_timeout(self, client):
        if self.deadline is None:
            return
        left = self.deadline - time.time()
        if left <= DEADLINE_PAD:
            return
        cap = max(0.01, left - DEADLINE_PAD)
        try:
            current = float(getattr(client, "timeout"))
            if current > 0:
                cap = min(cap, current)
        except (AttributeError, TypeError, ValueError, OverflowError):
            pass
        try:
            client.timeout = cap
        except Exception:
            pass

    def release(self):
        with self._condition:
            self.active_sends = max(0, self.active_sends - 1)
            if self.active_sends == 0:
                self._condition.notify_all()

    def stop_now(self):
        with self._condition:
            self.closed = True
            self.stop.set()
            while self.active_sends:
                self._condition.wait()


class _Replay:
    """Replay a recipe against ONE target. Never raises out of run()."""

    def __init__(self, url, *, deadline=None, max_requests=60, stop=None,
                 client_factory=None, coordinator=None):
        self.url = url
        self.deadline = deadline
        try:
            self.max_requests = 60 if max_requests is None else max(0, int(max_requests))
        except (TypeError, ValueError):
            self.max_requests = 60
        self.stop = stop or threading.Event()
        self.coordinator = coordinator if isinstance(coordinator, _RequestCoordinator) else None
        self.lock = threading.Lock()
        # A stop Event alone leaves a check/send race: a worker can reserve a
        # request, pause, and enter the client after the coordinator returns.
        # Keep direct wire reservations separate from result-state locking so
        # stop_now() can close and drain them without serialising targets.
        self._send_condition = threading.Condition()
        self._send_closed = False
        self._active_sends = 0
        self.requests = 0
        self.pages = []                 # [{path, status, text, payoff}]
        self.seen = {}                  # proof -> [(path, "payoff"|"plain")]
        self.payoff = set()             # proofs from a self-proving payoff step
        self.plain = set()              # proofs from a plain step
        self.baseline_incomplete = False
        self.candidate_incomplete = False
        self.candidate_payoff = {}      # different-shape candidate -> path, affirmed payoff only
        self.candidate_plain = set()    # candidate values seen without this response affirming success
        self.candidates = []            # bounded novel values surfaced, never returned
        self.flags = []                 # CourseStack-style flags surfaced for the player
        self.refused = []
        self.stopped = None
        self.where = None
        self.context = {}
        self.t0 = time.time()
        try:
            self.host = (urllib.parse.urlsplit(url).hostname or "").lower()
            if client_factory is not None:
                self.client = client_factory(url, REQUEST_TIMEOUT)
            else:
                self.client = _web.WebClient(url, timeout=REQUEST_TIMEOUT)
        except Exception as e:          # OutOfScope, a bad URL, an unreachable target
            self.host, self.client = "", None
            self.stopped = f"no client: {type(e).__name__}"

    def _left(self):
        return None if self.deadline is None else float(self.deadline) - time.time()

    def _may_send(self, *, include_shared_budget=True):
        if self._send_closed or self.stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.coordinator is not None:
            reason = self.coordinator.reason(include_budget=include_shared_budget)
            if reason is not None:
                self.stopped = self.stopped or reason
                return False
        left = self._left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def _reserve_send(self):
        with self._send_condition:
            if self._send_closed or self.stop.is_set():
                self.stopped = self.stopped or "stopped"
                return False
            if self.coordinator is not None:
                reason = self.coordinator.reserve()
                if reason is not None:
                    self.stopped = self.stopped or reason
                    return False
            self._active_sends += 1
            return True

    def _release_send(self):
        with self._send_condition:
            self._active_sends = max(0, self._active_sends - 1)
            if self._active_sends == 0:
                self._send_condition.notify_all()
        if self.coordinator is not None:
            self.coordinator.release()

    def _reserved_send_still_allowed(self):
        with self._send_condition:
            if self._send_closed or self.stop.is_set():
                self.stopped = self.stopped or "stopped"
                return False
            left = self._left()
            if left is not None and left <= DEADLINE_PAD:
                self.stopped = self.stopped or "deadline"
                return False
            if self.coordinator is not None and not self.coordinator.result_allowed():
                self.stopped = self.stopped or self.coordinator.reason(include_budget=False)
                return False
            return True

    def stop_now(self):
        """Close the wire gate and wait for every reserved/in-flight request."""
        with self._send_condition:
            self._send_closed = True
            while self._active_sends:
                self._send_condition.wait()

    def _allowed(self, path, headers):
        """GET-safe: same-host absolute path, no destructive word in the path (FHS `run` exempt) or in a
        query parameter name, and no destructive word in a request header name or value."""
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            return False
        base, _, query = path.partition("?")
        segs = [s for s in base.split("/") if s and s.lower() != "run"]
        if is_destructive("/" + "/".join(segs)):
            return False
        for k, _v in urllib.parse.parse_qsl(query, keep_blank_values=True):
            if is_destructive(k):
                return False
        for hk, hv in (headers or {}).items():
            if is_destructive(hk) or is_destructive(hv):
                return False
        return True

    def _get(self, path, headers, payoff):
        """One GET. Returns the page dict (or None) and records proofs/flags. Never raises."""
        if self.client is None:
            return None
        if not self._allowed(path, headers):
            self.refused.append(str(path)[:200])
            return None
        if not self._may_send() or not self._reserve_send():
            return None
        try:
            with self.lock:
                # The shared slot was consumed by _reserve_send(); the request
                # using the final slot remains valid while stop/deadline and
                # this replay's own cap are still checked.
                if not self._may_send(include_shared_budget=False):
                    return None
                self.requests += 1
            left = self._left()
            try:
                self.client.timeout = (REQUEST_TIMEOUT if left is None else
                                       max(0.2, min(REQUEST_TIMEOUT, left - 0.1)))
            except Exception:
                pass
            if self.coordinator is not None:
                self.coordinator.cap_timeout(self.client)
            if not self._reserved_send_still_allowed():
                return None
            try:
                r = self.client.request("GET", path, headers=dict(headers) if headers else None,
                                        allow_redirects=False)
            except Exception:
                return None
        finally:
            self._release_send()
        if self.coordinator is not None and not self.coordinator.result_allowed():
            self.stopped = self.stopped or self.coordinator.reason(include_budget=False)
            return None
        body = r.get("body")
        hdrs = r.get("response_headers") or {}
        pairs = r.get("response_header_pairs")
        if isinstance(pairs, (list, tuple)):
            header_pairs = [(str(row[0])[:1024], str(row[1])[:16_384])
                            for row in pairs[:512]
                            if isinstance(row, (list, tuple)) and len(row) == 2]
        else:
            header_pairs = ([(str(key)[:1024], str(value)[:16_384])
                             for key, value in list(hdrs.items())[:512]]
                            if isinstance(hdrs, dict) else [])
        framing_error = None
        try:
            _web._validate_stream_framing(r.get("status"), header_pairs)
        except Exception as exc:
            framing_error = str(exc)[:240]
        if _response_policy is not None and hasattr(_response_policy, "response_text_views"):
            try:
                views = ([] if framing_error else list(
                    _response_policy.response_text_views(r, strict=bool(payoff))))
            except Exception:
                views = []
        else:
            # A partial export has no safe decoder for declared carriers.
            declared = any(name.lower() in ("content-encoding", "transfer-encoding")
                           or (name.lower() == "content-type" and
                               (value.lower().startswith("multipart/")
                                or "application/zip" in value.lower()))
                           for name, value in header_pairs)
            raw_text = (bytes(body).decode("utf-8", "strict")
                        if isinstance(body, (bytes, bytearray)) else str(body or ""))
            views = [] if framing_error or declared else [raw_text]
        views = list(dict.fromkeys(str(value)[:MAX_CANDIDATE_TEXT] for value in views))[:256]
        text = views[0] if views else ""
        view_docs = [(view, _json_of(view)) for view in views]
        try:
            doc = _security_json.loads_unique(views, max_chars=MAX_CANDIDATE_TEXT)
        except Exception:
            doc = None
        # Tie proof extraction to THIS response's success signal.  A different payoff step affirming success
        # cannot bless a 403, a rejection, or an unaffirmed response which happens to print a proof-like decoy.
        # The proof must also occur in the SAME coherent carrier view as that affirmation: a JSON MIME member
        # containing {ok:true} cannot bless a bare proof in a sibling member or response header.
        affirming = [view for view, local in view_docs
                     if _response_affirms(r.get("status"), local)]
        effective_payoff = bool(not framing_error and payoff
                                and _response_affirms(r.get("status"), doc)
                                and len(affirming) == 1)
        payoff_view = affirming[0] if effective_payoff else None
        baseline_evidence = ""
        if not effective_payoff and _response_policy is not None \
                and hasattr(_response_policy, "response_baseline_text"):
            try:
                baseline_evidence = _response_policy.response_baseline_text(r)
                if _response_policy.baseline_set_incomplete([baseline_evidence]):
                    self.baseline_incomplete = True
            except Exception:
                self.baseline_incomplete = True
        page = {"path": path, "status": r.get("status"), "text": text, "payoff": effective_payoff,
                "designated_payoff": bool(payoff), "affirmed": effective_payoff,
                "headers": {str(k): str(v) for k, v in hdrs.items()},
                "response_header_pairs": header_pairs, "json": doc}
        if framing_error:
            page["framing_error"] = framing_error
        payoff_scan, plain_scan = set(), set()
        for view in views:
            found = set(scan_for_proofs(view, self.host))
            (payoff_scan if effective_payoff and view == payoff_view else plain_scan).update(found)
        for _name, value in header_pairs:
            plain_scan.update(scan_for_proofs(value, self.host))
        if not effective_payoff and baseline_evidence:
            plain_scan.update(scan_for_proofs(baseline_evidence, self.host))
        payoff_candidates, plain_candidates = [], []
        for view, local in view_docs:
            target = payoff_candidates if effective_payoff and view == payoff_view else plain_candidates
            candidate_integrity = {}
            for value in _candidate_values(view, local, _integrity=candidate_integrity):
                if value not in target:
                    target.append(value)
            if candidate_integrity.get("incomplete"):
                self.candidate_incomplete = True
        with self.lock:
            self.pages.append(page)
            for p in payoff_scan:
                self.seen.setdefault(p, []).append((path.split("?", 1)[0], "payoff"))
                self.payoff.add(p)
            for p in plain_scan:
                self.seen.setdefault(p, []).append((path.split("?", 1)[0], "plain"))
                self.plain.add(p)
            for value in payoff_candidates:
                self.candidate_payoff.setdefault(value, path.split("?", 1)[0])
            for value in plain_candidates:
                self.candidate_plain.add(value)
            for view in views:
                for f in _flags(view):
                    if f not in self.flags:
                        self.flags.append(f)
        return page

    def run(self, recipe):
        if self.client is None:
            self.where = "no-client"
            return None
        steps = recipe.get("steps") if isinstance(recipe, dict) else None
        if not isinstance(steps, list) or not steps:
            self.stopped = "recipe has no steps"
            self.where = "recipe"
            return None
        if len(steps) > MAX_STEPS:
            self.stopped = f"recipe has too many steps ({len(steps)} > {MAX_STEPS})"
            self.where = "recipe"
            return None
        # A step with any non-GET method is refused before anything is sent.
        for st in steps:
            m = (st.get("method") or st.get("verb") or "GET") if isinstance(st, dict) else ""
            if str(m).upper() != "GET":
                self.stopped = f"non-GET step refused: {str(m)[:20]} (writes are backlog row 513, the player's)"
                self.where = "method"
                return None

        if recipe.get("clues"):
            self._load_clues(recipe.get("clues_path") or "/api/clues")

        last_payoff = max((i for i, s in enumerate(steps) if isinstance(s, dict) and s.get("payoff")),
                          default=len(steps) - 1)
        for i, st in enumerate(steps):
            if not self._may_send():
                self.where = self.where or self.stopped or "stopped"
                return self._answer()
            payoff = bool(st.get("payoff")) or (i == last_payoff and not any(
                s.get("payoff") for s in steps if isinstance(s, dict)))
            path, missing = _resolve(st.get("get") or st.get("path"), self.context)
            if path is None:
                self.stopped = f"step {i}: no value for {{{missing}}}"
                self.where = f"step{i}"
                return self._answer()
            headers = {}
            ok_hdr = True
            for hk, hv in (st.get("headers") or {}).items():
                rhv, hmiss = _resolve(hv, self.context) if isinstance(hv, str) and "{" in hv else (hv, None)
                if rhv is None:
                    ok_hdr = False
                    self.stopped = f"step {i}: no value for header {{{hmiss}}}"
                    break
                headers[str(hk)] = str(rhv)
            if not ok_hdr:
                self.where = f"step{i}"
                return self._answer()
            page = self._get(path, headers, payoff)
            if page is None:
                # a refused/empty step is not fatal unless it was the payoff with nothing captured after
                continue
            doc = page.get("json")
            for var, sel in (st.get("capture") or {}).items():
                val = _select(doc, sel)
                if isinstance(val, (str, int, float)) and not isinstance(val, bool):
                    self.context[str(var)] = val
        self.where = "done"
        return self._answer()

    def _load_clues(self, path):
        """Bind /api/clues string fields as {clue.<field>} in the context (a plain, non-payoff read)."""
        p, _m = _resolve(path, self.context)
        if p is None:
            return
        page = self._get(p, None, payoff=False)
        doc = page.get("json") if page else None
        if isinstance(doc, dict):
            for k, v in doc.items():
                if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    self.context[f"clue.{k}"] = v

    def _answer(self):
        """The single self-proven proof, or None. The payoff step's response must AFFIRM success, the
        proof must be the one proof-like value seen anywhere, of the auto-submit wire form, and no plain page may
        have shown it (a decoy). Mirrors proof_hunt.answer() with the self-prove gate added."""
        with self.lock:
            seen = set(self.seen)
            affirmed = any(pg.get("payoff") for pg in self.pages)
            pay = {p for p in self.payoff if p not in self.plain}
            self.candidates = [v for v in self.candidate_payoff
                               if v not in self.candidate_plain and not is_proof(v)][:MAX_CANDIDATES]
        if self.baseline_incomplete or self.candidate_incomplete:
            self.stopped = self.stopped or (
                "candidate response incomplete" if self.candidate_incomplete
                else "baseline response incomplete")
            return None
        if not affirmed:
            self.stopped = self.stopped or ("no payoff affirmed success (ok/success/status)"
                                            if self.pages else "nothing fetched")
            return None
        if self.candidates:
            self.stopped = self.stopped or "successful payoff surfaced a different-shaped candidate"
            return None
        if len(seen) != 1 or pay != seen:
            self.stopped = self.stopped or ("several proof-like values" if len(seen) > 1 else
                                            "a proof on a plain page" if self.plain else
                                            "no proof in the payoff")
            return None
        p = next(iter(seen))
        if not is_proof(p):
            self.stopped = self.stopped or "proof form is not the auto-submit wire form"
            return None
        return p


# -- Outcome, apply, solve ------------------------------------------------------------------------------
def _outcome(r, proof):
    return {"proof": proof, "flags": list(r.flags), "where": r.where, "requests": r.requests,
            "refused": list(r.refused)[:20], "stopped": None if proof else r.stopped,
            "seen": {p: v[:4] for p, v in r.seen.items()}, "candidates": list(r.candidates)[:MAX_CANDIDATES],
            "baseline_incomplete": bool(r.baseline_incomplete),
            "candidate_incomplete": bool(r.candidate_incomplete),
            "seconds": round(time.time() - r.t0, 3)}


def apply_recipe(recipe, url, ctx=None):
    """Replay `recipe` against ONE target `url`. Returns an Outcome dict. Never raises."""
    ctx = dict(ctx or {})
    try:
        deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
    except (TypeError, ValueError):
        deadline = None
    try:
        max_requests = 60 if ctx.get("max_requests") is None else int(ctx.get("max_requests"))
    except (TypeError, ValueError):
        max_requests = 60
    r = _Replay(str(url), deadline=deadline, max_requests=max_requests,
                stop=ctx.get("_stop"), client_factory=ctx.get("client_factory"),
                coordinator=ctx.get("_request_coordinator"))
    registry = ctx.get("_replays")
    registry_lock = ctx.get("_replays_lock")
    answer_id = ctx.get("_answer_id")
    if isinstance(registry, dict) and answer_id is not None:
        try:
            if hasattr(registry_lock, "__enter__"):
                with registry_lock:
                    registry[answer_id] = r
            else:
                registry[answer_id] = r
        except Exception:
            pass
    try:
        proof = r.run(recipe if isinstance(recipe, dict) else {})
    except Exception as e:              # the contract: a target never raises
        r.stopped = r.stopped or f"error: {type(e).__name__}"
        proof = None
    proof = proof if is_proof(proof) else None
    return _outcome(r, proof)


def recover(recipe, targets, ctx=None):
    """Replay `recipe` against every target in parallel. Returns
        {"answers": {aid: proof}, "flags": [{answer_id, url, flag}], "targets": {aid: Outcome}}
    `answers` holds ONLY self-proven proofs of the auto-submit wire form (never a flag); flags are surfaced for the
    player and never banked. Never raises."""
    out = {"answers": {}, "flags": [], "targets": {}}
    try:
        ctx = dict(ctx or {})
        valid = [t for t in list(targets or []) if isinstance(t, dict) and t.get("answer_id") and t.get("url")]
    except Exception:
        return out
    stop = threading.Event()
    ctx["_stop"] = stop
    try:
        deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
    except (TypeError, ValueError):
        deadline = None
    try:
        shared_budget = 60 if ctx.get("max_requests") is None \
            else max(0, int(ctx.get("max_requests")))
    except (TypeError, ValueError, OverflowError):
        shared_budget = 60
    coordinator = ctx.get("_request_coordinator")
    if not isinstance(coordinator, _RequestCoordinator):
        coordinator = _RequestCoordinator(shared_budget, deadline=deadline, stop=stop)
    ctx["_request_coordinator"] = coordinator
    results = {}
    results_lock = threading.Lock()
    replays = {}
    replays_lock = threading.Lock()
    ctx["_replays"] = replays
    ctx["_replays_lock"] = replays_lock

    def one(t):
        aid = t["answer_id"]
        try:
            local_ctx = dict(ctx)
            local_ctx["_answer_id"] = aid
            value = apply_recipe(recipe, str(t["url"]), local_ctx)
        except Exception:
            value = {"proof": None, "flags": [], "where": "error", "requests": 0,
                     "refused": [], "stopped": "error", "seen": {}, "candidates": [], "seconds": 0.0}
        # A timed coordinator may have closed while bounded local response
        # processing was finishing. Never publish that late result.
        if not stop.is_set():
            with results_lock:
                if not stop.is_set():
                    results[aid] = value

    threads = [threading.Thread(target=one, args=(t,), name=f"web-patch-{t['answer_id']}", daemon=True)
               for t in valid]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=None if deadline is None else max(0.05, deadline - time.time()))
    stop.set()
    coordinator.stop_now()
    # Close every replay's direct send gate before observing results. A replay
    # created after this snapshot sees the already-set stop and cannot reserve.
    with replays_lock:
        active_replays = list(replays.values())
    for replay in active_replays:
        replay.stop_now()
    if deadline is None:
        for th in threads:
            th.join()
    else:
        drain_until = min(deadline, time.time() + 0.25)
        for th in threads:
            th.join(timeout=max(0.0, drain_until - time.time()))
    for t in valid:
        aid = t["answer_id"]
        oc = results.get(aid) or {"proof": None, "flags": [], "where": "timeout", "requests": 0,
                                  "refused": [], "stopped": "timeout", "seen": {}, "candidates": [],
                                  "seconds": 0.0}
        out["targets"][aid] = oc
        if oc.get("proof"):
            out["answers"][aid] = oc["proof"]
        for f in oc.get("flags") or []:
            out["flags"].append({"answer_id": aid, "url": t["url"], "flag": f})
        for value in list(oc.get("candidates") or [])[:6]:
            shown = str(value).replace("\r", " ").replace("\n", " ")[:256]
            line = f"WEB PROOF CANDIDATE {aid}: {shown} (successful response; not auto-submitted)"
            evidence = ctx.get("evidence")
            if isinstance(evidence, list) and line not in evidence:
                evidence.append(line)
            print(line, file=sys.stderr)
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), recipe, valid, out)
    return out


def solve_targets(recipe, targets, ctx=None):
    """proof_hunt's contract, with the recipe first: {answer_id: proof|None}. Never raises. Only a self-
    proven proof of the auto-submit wire form is a value; a flag is None here and surfaced through recover()."""
    res = recover(recipe, targets, ctx)
    out = {}
    for t in (targets or []):
        if isinstance(t, dict) and t.get("answer_id"):
            v = res["answers"].get(t["answer_id"])
            out[t["answer_id"]] = v if is_proof(v) else None
    return out


def _write_log(log_dir, challenge, recipe, targets, res):
    """One row per target in <log_dir>/web_patch.jsonl (paths only, no host). Never raises."""
    if not log_dir:
        return
    try:
        d = Path(log_dir)
        d.mkdir(parents=True, exist_ok=True)
        name = (recipe.get("name") if isinstance(recipe, dict) else None) or "recipe"
        with (d / "web_patch.jsonl").open("a", encoding="utf-8") as f:
            for t in targets:
                aid = t["answer_id"]
                oc = res["targets"].get(aid) or {}
                row = {"at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                       "challenge": challenge, "recipe": name, "answer_id": aid, "index": t.get("index"),
                       "proof": res["answers"].get(aid), "where": oc.get("where"),
                       "requests": oc.get("requests"), "seconds": oc.get("seconds"),
                       "stopped": oc.get("stopped"),
                       "seen": oc.get("seen", {}), "refused": oc.get("refused", []),
                       "candidates": list(oc.get("candidates") or [])[:MAX_CANDIDATES],
                       "flags": [x["flag"] for x in res.get("flags", []) if x.get("answer_id") == aid]}
                f.write(json.dumps(row) + "\n")
    except Exception:
        pass


# -- banking (the operator's; never wired into Layer 1) -------------------------------------------------
def write_answers(answers, path):
    """Write {answer_id: proof} to a JSON file for `tools/verify.py <id> --answers FILE`."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(answers, indent=1), encoding="utf-8")
    return str(p)


def verify_command(base_id, answers_path):
    """The exact command that banks the recovered proofs. One submission path: tools/verify.py."""
    return [".venv/bin/python", "tools/verify.py", str(base_id), "--answers", str(answers_path)]


def bank(recipe, base_id, targets, ctx=None, *, run=False):
    """Recover the proofs and, with run=True, bank them with tools/verify.py. Default run=False only builds
    the answers file and returns the command (the CLI runs it behind --bank). A flag is never in `answers`,
    so verify.py never sees one. Nothing here is called by Layer 1, the opener or a clock."""
    res = recover(recipe, targets, ctx)
    answers = {aid: p for aid, p in res["answers"].items() if is_proof(p)}
    log_dir = (ctx or {}).get("log_dir") or "."
    path = write_answers(answers, Path(log_dir) / f"web_patch_answers-{base_id}.json")
    cmd = verify_command(base_id, path)
    res["answers_file"] = path
    res["verify_command"] = cmd
    if run and answers:
        res["verify"] = subprocess.run(cmd, cwd=_repo_root(), capture_output=True, text=True).returncode
    return res


def _repo_root():
    return str(HERE.parent.parent)


# =======================================================================================================
#  Row 513: the auto-POST BRIDGE (the second capability of this file).
#
#  The recipe hook above replays a GET-only class an agent proved by hand. This bridge wires the already-built,
#  never-wrong, NON-DESTRUCTIVE POST exploiter (solvers/web/post_exploit.py) into Layer 1 so that a class which
#  REQUIRES a POST (an upload bypass, an intended state change the app itself publishes, a login with
#  caller-provided credentials) auto-banks the base / Time Trial / Mastery at the release -- WITHOUT relaxing any
#  guard. tools/web_open.py calls enabled()/auto_post() for an id the GET-only hunter left unanswered, and the web
#  agent runs it by hand (tools/web_agent.py post). The hard guards, re-enforced inside post_exploit.py and NEVER
#  relaxed (this crosses row 393's GET-only default, so it is airtight):
#    * DEFAULT OFF. In Layer 1 the bridge does nothing unless challenges/_opener.json says "webpost": "on" AND no
#      kill-switch is set. OFF, missing, or ANY error -> {} and the id waits for the web agent, exactly as today.
#    * NEVER a destructive HTTP verb (only GET/HEAD/OPTIONS/POST leave post_exploit._Client).
#    * POST only where the class REQUIRES it and one target-owned object explicitly, coherently advertises POST,
#      its route and its inert field shape. Generic/GET/conflicting contracts authorize nothing; every main and
#      auxiliary route is then rechecked by post_exploit's fixed-point same-origin/destructive-query guard.
#    * A FLAG is ALWAYS None + surfaced as a COURSESTACK FLAG line, NEVER auto-submitted.
#    * Bank a proof ONLY when the target self-proves it (one-proof rule, wire form); nothing is banked here, the
#      judged proof is RETURNED for Layer 1 / the agent to bank with tools/verify.py.
#    * NEVER execute returned code -- every response is untrusted DATA, scanned with regexes only.
# =======================================================================================================

OFF_ENV = "CTF_WEB_POST"
OFF_FILE = "_web_post.off"

# Read-only endpoints an app uses to publish its clue / route inventory. GET only; parsed as JSON (data, never run).
CLUE_PATHS = ("/api/clues", "/api/inventory", "/clues", "/inventory", "/")
CLUE_READ_BUDGET = 6          # at most this many recon GETs before the POST classes run

# A clue key whose VALUE names an advertised route for each POST class. Matched case-insensitively and exactly, so
# only a route the app itself publishes is ever used; a path is never guessed or assembled from a word.
_UPLOAD_ROUTE_KEYS = ("upload_route", "upload_path", "upload_url", "upload_endpoint")
_UPLOAD_FETCH_KEYS = ("fetch_route", "fetch_template", "read_route", "files_route", "download_route")
_STATE_ROUTE_KEYS = ("feature_route", "action_route", "submit_route", "state_route", "apply_route")
_STATE_READ_KEYS = ("result_route", "proof_route", "read_route", "status_route")
_STATE_FIELDS_KEYS = ("fields", "parameters", "params", "body", "payload")
_METHOD_KEYS = ("method", "request_method", "http_method", "feature_method", "state_method",
                "action_method", "submit_method", "upload_method")
_NONCE_FIELD_KEYS = ("nonce_field", "echo_field", "marker_field", "token_field")
_MISSING = object()
_CONFLICT = object()


def _challenges_root():
    """The event workdir, ctf.paths.workdir(): $CTF_WORKDIR, else ~/ctf-work/<event>. Resolved on every
    call (a test or rehearsal moves it after import); raises ctf.event.EventError when neither resolves."""
    return ctf_paths.workdir()


def enabled():
    """True only when Layer 1 may auto-fire the POST classes. Default False; any doubt is False (fail-safe).
    In master always False: the webpost gate's switch file is archived (WEBPOST_GATE says so)."""
    return False


def _as_dicts(response):
    """Nested objects from one unambiguous target JSON document."""
    out = []
    try:
        if isinstance(response, dict) and _response_policy is not None:
            views = _response_policy.response_text_views(response)
            obj = _security_json.loads_unique(views, max_chars=MAX_CANDIDATE_TEXT)
        else:
            body = response.get("body") if isinstance(response, dict) else response
            text = (bytes(body).decode("utf-8", "strict")
                    if isinstance(body, (bytes, bytearray)) else str(body or ""))
            obj = _security_json.loads(text, max_chars=MAX_CANDIDATE_TEXT)
    except Exception:
        return out
    # security_json has already bounded nodes/depth/members.  Walk every one:
    # silently stopping at an arbitrary prefix lets a late conflicting
    # contract be hidden behind harmless filler.
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            out.append(cur)
            stack.extend(v for v in cur.values() if isinstance(v, (dict, list)))
        elif isinstance(cur, list):
            stack.extend(v for v in cur if isinstance(v, (dict, list)))
    return out


def _canonical_mapping(clue):
    """One policy object, rejecting case/punctuation/camel collisions."""
    if not isinstance(clue, dict):
        return None
    out = {}
    for raw_key, value in clue.items():
        if not isinstance(raw_key, str):
            return None
        try:
            key = _security_json.canonical_key(raw_key)
        except Exception:
            key = re.sub(r"[^a-z0-9]+", "_", re.sub(
                r"([a-z0-9])([A-Z])", r"\1_\2", raw_key).lower()).strip("_")
        if not key or key in out:
            return None
        out[key] = value
    return out


def _has_route_surface(clue):
    """Whether an object purports to name any bridge route, even ambiguously."""
    if not isinstance(clue, dict):
        return False
    route_keys = set(_UPLOAD_ROUTE_KEYS + _UPLOAD_FETCH_KEYS + _STATE_ROUTE_KEYS + _STATE_READ_KEYS)
    canonical_routes = {_security_json.canonical_key(key) for key in route_keys}
    for raw_key in clue:
        if isinstance(raw_key, str) and _security_json.canonical_key(raw_key) in canonical_routes:
            return True
    return False


def _coherent(clues, keys, normalize):
    """The one normalized value all present aliases agree on."""
    values = []
    for key in keys:
        canonical = _security_json.canonical_key(key)
        if canonical not in clues:
            continue
        try:
            value = normalize(clues[canonical])
        except Exception:
            return _CONFLICT
        if value is None:
            return _CONFLICT
        values.append(value)
    if not values:
        return _MISSING
    first = values[0]
    return first if all(value == first for value in values[1:]) else _CONFLICT


def _route_value(value):
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    route = value
    if _pe is None or _pe._looks_destructive_path(route):
        return None
    if route.startswith("/") or re.match(r"(?i)^https?://", route):
        return route
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./?&=%+;,-]*", route):
        return "/" + route
    return None


def _find_route(clues, keys):
    """One non-destructive route only when every present alias agrees."""
    value = _coherent(clues, keys, _route_value)
    return value if value not in (_MISSING, _CONFLICT) else None


def _field_names(value):
    if isinstance(value, dict):
        raw_names = list(value)
    elif isinstance(value, list):
        raw_names = value
    else:
        return None
    if not raw_names or len(raw_names) > 128:
        return None
    names, canonical_seen = [], set()
    for raw_name in raw_names:
        if not isinstance(raw_name, (str, int)):
            return None
        name = str(raw_name)
        canonical = re.sub(r"[^a-z0-9]+", "_", re.sub(
            r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()).strip("_")
        if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", name)
                or not canonical or canonical in canonical_seen
                or (_pe is not None and _pe._ACTIVE_FIELD_NAME.search(canonical))):
            return None
        canonical_seen.add(canonical)
        names.append(name)
    return tuple(sorted(names))


def _state_fields(clues):
    """The field names the clues advertise for an intended state-change form, as {name: ""} placeholders. The
    values are left empty: the proof is read from the POST response by the one-proof rule, never guessed in."""
    names = _coherent(clues, _STATE_FIELDS_KEYS, _field_names)
    if names in (_MISSING, _CONFLICT):
        return {}
    # Target-provided values are never instructions.  Only the advertised,
    # inert field names survive; locally generated nonces are added later.
    return {name: "" for name in names}


def _hints_from_one_clue(clue):
    """Derive target-authorized POST hints from one coherent JSON object.

    A route, its fields, and its readback must not be assembled from sibling
    objects or different clue endpoints.  That turns benign diagnostics into a
    conservative false negative instead of an authority-confusion POST.
    """
    normalized = _canonical_mapping(clue)
    if normalized is None:
        return {}
    hints = {}

    method = _coherent(normalized, _METHOD_KEYS,
                       lambda value: value.strip().upper() if isinstance(value, str) else None)
    if method is _CONFLICT:
        return {}

    upload_value = _coherent(normalized, _UPLOAD_ROUTE_KEYS, _route_value)
    state_value = _coherent(normalized, _STATE_ROUTE_KEYS, _route_value)
    fetch_value = _coherent(normalized, _UPLOAD_FETCH_KEYS, _route_value)
    read_value = _coherent(normalized, _STATE_READ_KEYS, _route_value)
    field_names = _coherent(normalized, _STATE_FIELDS_KEYS, _field_names)
    nonce_name = _coherent(normalized, _NONCE_FIELD_KEYS, lambda value: (
        value if isinstance(value, str) and _field_names([value]) is not None else None))
    if any(value is _CONFLICT for value in (
            upload_value, state_value, fetch_value, read_value, field_names, nonce_name)):
        return {}

    # No bridge POST without an explicit POST method in this same object.
    # A generic feature_route or an explicitly GET-only route is read-only
    # evidence, never state-change authority.
    upload_contract = method == "POST" and upload_value is not _MISSING
    state_contract = (method == "POST" and state_value is not _MISSING
                      and field_names is not _MISSING)
    # One clue object must authorize one automatic POST class.  Advertising
    # two unrelated write surfaces is inventory, not an unambiguous action.
    if upload_contract and state_contract:
        return {}

    if upload_contract:
        hints["upload_path"] = upload_value
        if fetch_value is not _MISSING:
            if (isinstance(fetch_value, str) and fetch_value.count("{filename}") == 1
                    and fetch_value.replace("{filename}", "hx-safe.bin").count("{") == 0
                    and fetch_value.replace("{filename}", "hx-safe.bin").count("}") == 0):
                hints["fetch_template"] = fetch_value
            else:
                return {}

    # State POST authority requires route + POST + an explicit, safe field
    # shape.  Empty/missing fields and method/action/role controls are refused.
    if state_contract:
        hints["state_path"] = state_value
        hints["state_fields"] = {name: "" for name in field_names}
        # A field the app says it echoes lets the POST response self-prove it processed OURS.
        if nonce_name is not _MISSING:
            hints["state_nonce_field"] = nonce_name
        if read_value is not _MISSING and read_value != state_value:
            hints["state_read_paths"] = [read_value]
    return hints


def derive_hints(clue_dicts, ctx):
    """Build hints from exactly one unambiguous target clue contract.

    Repeated byte-equivalent contracts are harmless.  Distinct objects that
    advertise different routes or enrich one another are ambiguous, so no
    automatic POST is authorized.  Caller-supplied credentials remain a
    separate explicit hand-tool authority and are never inferred from target
    responses.
    """
    contracts = []
    invalid_route_surface = False
    try:
        candidates = list(clue_dicts or [])
    except Exception:
        return {}
    if len(candidates) > getattr(_security_json, "DEFAULT_MAX_NODES", 40_000):
        return {}
    for clue in candidates:
        hints = _hints_from_one_clue(clue)
        if not hints:
            if _has_route_surface(clue):
                invalid_route_surface = True
            continue
        try:
            signature = json.dumps(hints, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError):
            continue
        if all(existing[0] != signature for existing in contracts):
            contracts.append((signature, hints))
            if len(contracts) > 1:
                return {}
    hints = dict(contracts[0][1]) if contracts and not invalid_route_surface else {}

    # login: only with credentials the CALLER provides (post_exploit never guesses or brute-forces). Layer 1 has
    # none, so this never auto-fires; the agent may pass them by hand (force path).
    creds = ctx.get("credentials") if isinstance(ctx, dict) else None
    if isinstance(creds, dict) and creds:
        hints["credentials"] = dict(creds)
        if isinstance(ctx.get("login_path"), str):
            hints["login_path"] = ctx["login_path"]
        if isinstance(ctx.get("read_paths"), list):
            hints["read_paths"] = list(ctx["read_paths"])

    return hints


def _read_clues(client, evidence):
    """GET the read-only clue/inventory endpoints and collect every JSON object they publish. GET only; a budget
    bounds the reads; a flag seen on these plain pages is still surfaced (never submitted)."""
    dicts = []
    seen_paths = set()
    for path in CLUE_PATHS:
        if client.sent >= CLUE_READ_BUDGET or path in seen_paths:
            continue
        seen_paths.add(path)
        try:
            r = client.get(path)
        except _pe.RequestBudget:
            break
        except Exception:
            continue
        for d in _as_dicts(r):
            dicts.append(d)
    return dicts


def new_post_request_coordinator(deadline=None, max_requests=None, stop=None):
    """Build the one wire gate for an entire auto-POST target set.

    ``tools/web_open.py`` creates it before starting its worker so the outer
    coordinator can close and drain the gate even if ``auto_post`` is delayed
    before its first target. The direct/agent path uses the same helper.
    """
    if _pe is None:
        return None
    budget = _pe.MAX_REQUESTS if max_requests is None else max_requests
    return _pe.RequestCoordinator(budget, deadline=deadline, stop=stop)


def auto_post(targets, ctx=None, force=False):
    """Run the never-wrong non-destructive POST classes a target's OWN clues advertise. Returns {answer_id: judged
    proof}; collects COURSESTACK FLAG and refusal lines into ctx['evidence']. Never raises. See the guards above.
    With force=False it returns {} immediately unless enabled(); force=True is the agent's by-hand path (which
    submits nothing) and ignores the switch but keeps every guard."""
    out = {}
    ctx = ctx if isinstance(ctx, dict) else {}
    evidence = ctx.setdefault("evidence", []) if isinstance(ctx.get("evidence", []), list) else []
    gate = None
    try:
        if _pe is None:
            return out
        if not force and not enabled():
            return out
        try:
            deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
        except (TypeError, ValueError):
            deadline = None
        raw_budget = ctx.get("max_requests")
        try:
            budget = _pe.MAX_REQUESTS if raw_budget is None else max(0, int(raw_budget))
        except (TypeError, ValueError, OverflowError):
            budget = _pe.MAX_REQUESTS
        stop = ctx.get("_post_stop") or ctx.get("_stop")
        supplied_gate = ctx.get("_post_gate")
        gate = (supplied_gate if isinstance(supplied_gate, _pe.RequestCoordinator)
                else new_post_request_coordinator(deadline, budget, stop))
        if gate is None:
            return out
        ctx["_post_gate"] = gate
        for t in list(targets or []):
            if not isinstance(t, dict):
                continue
            aid, url = t.get("answer_id"), t.get("url")
            if not (isinstance(aid, str) and isinstance(url, str) and url):
                continue
            if not gate.available():
                break
            try:
                client = _pe._wrap_client(
                    url, {"max_requests": budget, "deadline": deadline, "stop": stop,
                          "_request_coordinator": gate})
            except Exception as e:
                evidence.append(f"web_patch {aid}: no scoped client ({type(e).__name__}); left to the agent")
                continue
            try:
                clue_dicts = _read_clues(client, evidence)
                hints = derive_hints(clue_dicts, ctx)
                if not hints:
                    evidence.append(f"web_patch {aid}: the target advertises no POST route; nothing POSTed")
                    continue
                res = _pe.post_exploit(client, hints)
            except _pe.DestructiveVerb as e:
                # A destructive verb means a wiring bug and was NOT sent; surface it, bank nothing, agent goes on.
                evidence.append(f"web_patch {aid}: refused a destructive verb ({e}); left to the agent")
                continue
            except Exception as e:
                evidence.append(f"web_patch {aid}: post_exploit error ({type(e).__name__}); left to the agent")
                continue
            for line in res.get("evidence") or []:
                evidence.append(f"[{aid}] {line}")
            proof = res.get("proof")
            if gate.result_allowed() and isinstance(proof, str) and _pe.judge_proof_value(proof):
                out[aid] = proof.strip()
    except Exception:
        # Any unexpected failure of the whole bridge is fail-safe: whatever was proven stands, the rest waits.
        return out
    finally:
        if gate is not None:
            gate.stop_now()
            ctx["_post_requests"] = gate.sent
    return out


# -- CLI ------------------------------------------------------------------------------------------------
def _targets_from_start(challenge):
    base = ctf_paths.workdir()
    for day in sorted(base.glob("day-*")):
        cdir = day / challenge
        sp = cdir / "start.json"
        if sp.exists():
            try:
                doc = json.loads(sp.read_text(encoding="utf-8"))
            except Exception:
                return [], str(cdir)
            tgts = []
            for i, t in enumerate(doc.get("targets") or [], 1):
                url = t.get("url") if isinstance(t, dict) else t
                aid = (t.get("answer_id") if isinstance(t, dict) else None) or f"proof-{i}"
                if url:
                    tgts.append({"answer_id": aid, "url": url, "index": i})
            return tgts, str(cdir)
    return [], None


def _recipe_main(argv=None):
    """The GET-only recipe-replay CLI (the operator's; it banks a recovered proof only with --bank)."""
    ap = argparse.ArgumentParser(description="replay a web recipe against a challenge's targets (GET only)")
    ap.add_argument("recipe")
    ap.add_argument("challenge")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--max-requests", type=int, default=60)
    ap.add_argument("--target", action="append", default=[], metavar="AID=URL")
    ap.add_argument("--bank", action="store_true", help="run tools/verify.py on the recovered proofs")
    args = ap.parse_args(argv)
    try:
        recipe = json.loads(Path(args.recipe).read_text(encoding="utf-8"))
    except Exception as e:
        print(json.dumps({"error": f"unreadable recipe: {type(e).__name__}"}))
        return 1
    if args.target:
        targets, log_dir = [], "."
        for i, spec in enumerate(args.target, 1):
            aid, _, url = spec.partition("=")
            if url:
                targets.append({"answer_id": aid, "url": url, "index": i})
    else:
        targets, log_dir = _targets_from_start(args.challenge)
    if not targets:
        print(json.dumps({"error": "no targets (pass --target AID=URL or write start.json)",
                          "challenge": args.challenge}))
        return 1
    ctx = {"deadline": time.time() + args.seconds, "max_requests": args.max_requests,
           "log_dir": log_dir, "challenge": args.challenge}
    res = bank(recipe, args.challenge, targets, ctx, run=args.bank)
    print(json.dumps({"answers": res["answers"], "flags": res["flags"],
                      "answers_file": res.get("answers_file"),
                      "verify": " ".join(res.get("verify_command", []))}, indent=1))
    for fl in res["flags"]:
        print(f"COURSESTACK FLAG {args.challenge}: {fl['flag']}", file=sys.stderr)
    return 0 if res["answers"] else 2


# -- CLI (the row-513 POST bridge, by hand: tools/web_agent.py post runs THIS entry) -------------------
#  It derives hints from the live target's OWN advertised clues and runs post_exploit. It SUBMITS NOTHING:
#  a returned judged proof (proof_<32hex>) is banked by hand with `tools/verify.py <id> --answers FILE`, and a
#  CourseStack flag is surfaced for the player, never auto-submitted.
def _targets_for_challenge(challenge):
    """The challenge's targets from its saved start.json, via proof_hunt's own reader (so the agent's post path
    sees exactly the targets the hunter saw). Returns [] when no start.json / no targets yet."""
    start_path = _ph._find_start(challenge)
    if start_path is None:
        return []
    try:
        return _ph.targets_from_start(json.loads(start_path.read_text()))
    except Exception:
        return []


def _bridge_main(argv):
    ap = argparse.ArgumentParser(description="web POST bridge (by hand): runs the never-wrong non-destructive "
                                             "post_exploit against routes the target's clues advertise; submits nothing")
    ap.add_argument("challenge", help="a web challenge id with a saved start.json (its target is read from clues)")
    ap.add_argument("--hints", help="path to a JSON hints file (credentials / routes the agent provides)", default=None)
    ap.add_argument("--max-requests", type=int, default=(_pe.MAX_REQUESTS if _pe else 40))
    args = ap.parse_args(argv)
    if _pe is None:
        print("WEB POST ABSENT: solvers/web/post_exploit.py is not importable; go on by hand", file=sys.stderr)
        return 3
    targets = _targets_for_challenge(args.challenge)
    if not targets:
        print(json.dumps({"error": "no targets in start.json yet for this challenge", "challenge": args.challenge}))
        return 1
    ctx = {"max_requests": args.max_requests, "evidence": []}
    if args.hints:
        try:
            ctx.update(json.loads(Path(args.hints).read_text()))
        except Exception as e:
            print(f"unreadable hints: {type(e).__name__}", file=sys.stderr)
            return 1
    # The agent invoked it by hand, so the switch is bypassed (force=True); every guard in post_exploit still holds.
    out = auto_post(targets, ctx, force=True)
    print(json.dumps(out, indent=1))
    for line in ctx.get("evidence", []):
        print(line, file=sys.stderr)
    return 0 if out else 2


def main(argv=None):
    """Dispatch: a readable `.json` recipe file as the first argument is the GET-only recipe-replay CLI; anything
    else (a challenge id, as tools/web_agent.py post passes) is the row-513 POST bridge CLI."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and str(argv[0]).endswith(".json") and Path(argv[0]).is_file():
        return _recipe_main(argv)
    return _bridge_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
