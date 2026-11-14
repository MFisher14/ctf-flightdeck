"""The live-service scope guard: the one check every network client runs before it opens a connection.

    from ctf import scope
    scope.check_host("web-1.x.example", 443, what="WebClient('https://web-1.x.example/')")
    scope.check_url("http://10.1.2.3:8080/chat")
    scope.policy()                       # ScopePolicy(event, scope, platform)

The web client (solvers/toolkits/web.py `WebClient`, `RawSocketScope`), the chat client
(solvers/toolkits/chat_target.py `ChatTarget`) and the pwn client (solvers/toolkits/pwn_target.py
`PwnTarget`) call it from their constructors, so a refusal happens before any socket is opened and
before any name is resolved. Each client passes its own `OutOfScope` subclass as `error`, so callers
that catch the client's error keep working and `except ctf.scope.OutOfScope` catches all of them.

The rules, read from the current event profile (ctf.event.current(), or the pinned profile) on every
call:

1. No profile, or a profile that does not load: refused, naming the EventError. There is no default
   scope.
2. `rules.live_service_scope` empty: refused. An empty scope means no live service may be contacted.
3. The event platform (scoreboard / CTFd / Game Master) is never a target: the host and port of
   `platform.base_url` and of $CTF_PLATFORM_URL (and its legacy spellings) are refused even when a
   scope glob matches them. The port matters: a challenge instance on another port of the same
   host is a target if the scope allows the host.
4. Otherwise the host must match a scope entry:
     - a host glob (fnmatch, case-insensitive; `*` also spans dots): "*.x.example", "web-?.x.example",
       "10.13.37.*", "localhost";
     - an IP network in CIDR form ("10.0.0.0/8", "fd00::/8"), matched against an IP-literal host.
   A hostname is matched by name only; nothing is resolved here. A glob made only of wildcards and
   dots ("*", "*.*") is rejected as too broad: it would let any non-CTF host through.
5. Player-pointed services (B-173). When the profile says rules.pointed_services = "allowed", a
   challenge service the player pointed at (`python -m ctf policy point <id> <host[:port]>`, a
   "scope.pointed" ledger record in the event workdir; "scope.unpointed" withdraws it) is also a
   target: the exact host, and the exact port when the point names one. It never opens the platform
   (rule 3 runs first), and with pointed_services "forbidden" (the default) the records are not read.
   A ledger that cannot be read refuses (fail closed).

Two more checks for code that is not a challenge client (R-13):

- `check_platform_url(url)`: a platform client (speedrun/wire.py's fast CTFd) may contact only the
  event platform, by host and port: `platform.base_url` or $CTF_PLATFORM_URL. Anything else, a
  challenge host included, is refused. No profile, or a profile with no platform URL: refused.
- `check_public_fetch(url, purpose=...)`: a fetch from a public third-party host (a symbol server, a
  package mirror, a tunnel service) needs an explicit entry in the profile's
  `rules.public_fetch_allow` (host globs or CIDR networks, the same syntax and the same too-broad
  rule as live_service_scope). An empty list refuses every public fetch, naming the host, the
  purpose and the key to add. The event platform is refused even when an entry matches it.
  live_service_scope does not open a public fetch, and public_fetch_allow does not open a target.

`pin(profile)` fixes the profile for this process (the test suite pins a test-only profile; a tool run
with an explicit event can pin that one); `unpin()` returns to event.current().
"""
from __future__ import annotations

import fnmatch
import ipaddress
import urllib.parse
from dataclasses import dataclass

from . import env, event, ledger, paths

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
POINTED = "scope.pointed"          # ledger record: the player pointed at a challenge service (B-173)
UNPOINTED = "scope.unpointed"      # ledger record: that point is withdrawn


class OutOfScope(ValueError):
    """A live target the current event profile does not allow. Raised before any connection."""


@dataclass(frozen=True)
class ScopePolicy:
    event: str                                    # the profile slug
    scope: tuple[str, ...]                        # rules.live_service_scope, as written
    platform: frozenset[tuple[str, int]]          # (host, port) pairs that are never targets
    pointed: tuple[tuple[str, int | None], ...] = ()   # player-pointed services (host, port or None)


_pinned: event.EventProfile | None = None


def pin(profile: event.EventProfile) -> None:
    """Use `profile` for every later check in this process instead of event.current()."""
    global _pinned
    if not isinstance(profile, event.EventProfile):
        raise TypeError(f"scope.pin needs an EventProfile, got {type(profile).__name__}")
    _pinned = profile


def unpin() -> None:
    global _pinned
    _pinned = None


def pinned() -> event.EventProfile | None:
    return _pinned


def _profile(profile: event.EventProfile | None) -> event.EventProfile:
    if profile is not None:
        return profile
    if _pinned is not None:
        return _pinned
    return event.current()


def _norm_host(host: str) -> str:
    h = str(host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def split_url(url: str) -> tuple[str, int | None]:
    """(host, port) of a URL; the port defaults by scheme (http/ws 80, https/wss 443), else None."""
    parts = urllib.parse.urlsplit(str(url))
    host = _norm_host(parts.hostname or "")
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = DEFAULT_PORTS.get(parts.scheme.lower())
    return host, port


def _platform_pairs(profile: event.EventProfile) -> frozenset[tuple[str, int]]:
    out = set()
    for url in (profile.platform.base_url, env.get("CTF_PLATFORM_URL")):
        if not url:
            continue
        host, port = split_url(url if "://" in url else "https://" + url)
        if host:
            out.add((host, port or 443))
    return frozenset(out)


def _too_broad(entry: str) -> bool:
    return not entry.replace("*", "").replace("?", "").replace(".", "").strip()


def _check_entries(slug: str, key: str, entries, error: type[OutOfScope]) -> None:
    for entry in entries:
        if _too_broad(entry):
            raise error(f"event {slug!r} rules.{key} entry {entry!r} is too broad: it would "
                        f"match any non-CTF host; list the event's own hosts or networks")
        if "/" in entry:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise error(f"event {slug!r} rules.{key} entry {entry!r} contains '/' but "
                            f"is not an IP network (CIDR)") from None


def policy(profile: event.EventProfile | None = None, *, error: type[OutOfScope] = OutOfScope) -> ScopePolicy:
    """The scope in force. Raises `error` when no profile can be loaded or a scope entry is unusable."""
    try:
        prof = _profile(profile)
    except event.EventError as e:
        raise error(f"no live-service scope: the event profile did not load ({e}); "
                    f"set CTF_EVENT to an event whose rules.live_service_scope lists the target") from e
    _check_entries(prof.slug, "live_service_scope", prof.rules.live_service_scope, error)
    return ScopePolicy(event=prof.slug, scope=tuple(prof.rules.live_service_scope),
                       platform=_platform_pairs(prof), pointed=pointed(prof, error=error))


def pointed(profile: event.EventProfile | None = None, *,
            error: type[OutOfScope] = OutOfScope) -> tuple[tuple[str, int | None], ...]:
    """The player-pointed services in force, oldest first: (host, port or None). Empty unless the
    profile has rules.pointed_services = "allowed". The latest record for a (host, port) wins."""
    try:
        prof = _profile(profile)
    except event.EventError as e:
        raise error(f"no live-service scope: the event profile did not load ({e})") from e
    if prof.rules.pointed_services != "allowed":
        return ()
    live: dict[tuple[str, int | None], bool] = {}
    try:
        for r in ledger.read(paths.workdir(prof.slug)):
            if r.get("event") in (POINTED, UNPOINTED) and r.get("event_slug") == prof.slug:
                key = (_norm_host(r.get("host", "")), r.get("port"))
                live.pop(key, None)
                if r["event"] == POINTED and key[0]:
                    live[key] = True
    except (OSError, ValueError) as e:
        raise error(f"event {prof.slug!r}: the player-pointed services could not be read from the "
                    f"ledger ({e}); refusing rather than guessing the scope") from e
    return tuple(live)


def _matches(host: str, entry: str) -> bool:
    if "/" in entry:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
    return fnmatch.fnmatchcase(host, _norm_host(entry))


def check_host(host: str, port: int | None = None, *, what: str | None = None,
               profile: event.EventProfile | None = None,
               error: type[OutOfScope] = OutOfScope) -> str:
    """Return the normalised host when `host` (on `port`) may be contacted under the event profile,
    else raise `error` naming the reason. Opens no connection and resolves no name."""
    what = what or repr(host)
    h = _norm_host(host)
    if not h:
        raise error(f"{what} has no host")
    pol = policy(profile, error=error)
    if not pol.scope and not pol.pointed:
        raise error(f"{what} refused: event {pol.event!r} has an empty rules.live_service_scope, so no live "
                    f"service may be contacted")
    for p_host, p_port in pol.platform:
        if h == p_host and (port is None or int(port) == p_port):
            raise error(f"{what} is the event platform ({p_host}:{p_port}: scoreboard / CTFd / Game Master), "
                        f"never a challenge target")
    if any(_matches(h, e) for e in pol.scope):
        return h
    if any(h == p_host and (p_port is None or (port is not None and int(port) == int(p_port)))
           for p_host, p_port in pol.pointed):
        return h
    listed = ", ".join(pol.scope) or "empty"
    extra = ""
    if pol.pointed:
        extra = "; no player-pointed service matches (" + ", ".join(
            p_host if p_port is None else f"{p_host}:{p_port}" for p_host, p_port in pol.pointed) + ")"
    raise error(f"{what} is outside event {pol.event!r} rules.live_service_scope "
                f"({listed}){extra}; not a CTF host for this event")


def check_url(url: str, *, what: str | None = None, profile: event.EventProfile | None = None,
              error: type[OutOfScope] = OutOfScope) -> str:
    """check_host for the host and port of an absolute URL."""
    host, port = split_url(url)
    return check_host(host, port, what=what or repr(url), profile=profile, error=error)


def check_platform_url(url: str, *, what: str | None = None, profile: event.EventProfile | None = None,
                       error: type[OutOfScope] = OutOfScope) -> tuple[str, int]:
    """(host, port) when `url` is the event platform (`platform.base_url` or $CTF_PLATFORM_URL,
    compared by host and port), else raise `error`. For platform clients only: a challenge host, a
    public host or a platform URL from another event is refused. Opens no connection."""
    what = what or repr(url)
    host, port = split_url(url)
    if not host:
        raise error(f"{what} has no host")
    try:
        prof = _profile(profile)
    except event.EventError as e:
        raise error(f"{what} refused: no event platform: the event profile did not load ({e}); "
                    f"set CTF_EVENT to the event whose platform.base_url this is") from e
    pairs = _platform_pairs(prof)
    if not pairs:
        raise error(f"{what} refused: event {prof.slug!r} has no platform.base_url and CTF_PLATFORM_URL is "
                    f"unset, so no platform may be contacted")
    if (host, port or 443) not in pairs:
        known = ", ".join(f"{h}:{p}" for h, p in sorted(pairs))
        raise error(f"{what} is not the platform of event {prof.slug!r} ({known}); a platform client "
                    f"contacts only that host and port")
    return host, port or 443


def check_public_fetch(url: str, *, purpose: str, profile: event.EventProfile | None = None,
                       error: type[OutOfScope] = OutOfScope) -> str:
    """Return the normalised host when a fetch of `url` (a public mirror, symbol server or tunnel
    service: not a challenge target) is allowed by the profile's rules.public_fetch_allow, else raise
    `error` naming the host, `purpose` and the profile key to add. Opens no connection and resolves
    no name. `url` may be a bare host name."""
    if not purpose:
        raise ValueError("check_public_fetch needs a purpose (what the fetch is for)")
    if "://" in str(url):
        host, port = split_url(url)
    else:
        host, port = _norm_host(url), None
    if not host:
        raise error(f"{purpose}: {url!r} has no host")
    try:
        prof = _profile(profile)
    except event.EventError as e:
        raise error(f"{purpose}: fetch from public host {host} refused: the event profile did not load ({e}); "
                    f"set CTF_EVENT to an event whose rules.public_fetch_allow lists it") from e
    allow = prof.rules.public_fetch_allow
    _check_entries(prof.slug, "public_fetch_allow", allow, error)
    for p_host, p_port in _platform_pairs(prof):
        if host == p_host and (port is None or int(port) == p_port):
            raise error(f"{purpose}: {host} is the event platform ({p_host}:{p_port}), never a public mirror")
    if not any(_matches(host, e) for e in allow):
        listed = ", ".join(allow) if allow else "empty"
        raise error(f"{purpose}: fetch from public host {host} refused: event {prof.slug!r} "
                    f"rules.public_fetch_allow ({listed}) does not list it; add \"{host}\" to "
                    f"rules.public_fetch_allow in events/{prof.slug}/event.toml to allow it")
    return host
