"""Client for a challenge page's own map-pin checker (B-113; a helper of osint_geolocate.py).

Some OSINT geolocation challenges are not answered on the platform: the challenge page shows a photo
or a panorama beside a map, a click posts the pinned latitude and longitude to the page's own
endpoint (``?check=1``), and the JSON reply carries the flag when the pin is close enough.  The flag
is then submitted on the platform like any other.  This module is the scriptable half of that:

    detect_checker_page(html, page_url)   is this such a page; where is the endpoint; what does it take
    GeoChecker.from_page(url, cid)        read the page once and build a checker for it; a field name
                                          or encoding the page does not show is refused, not guessed
    GeoChecker(url, cid, check_url=...)   or name the endpoint (and its fields) by hand
    checker.check(lat, lon)               ONE capped, paced POST -> CheckOutcome (flags, ok, message)

Guards, in the order they run:

  scope     the page URL goes through the live-service scope guard (:func:`ctf.scope.check_url`) in
            the constructor, before any request; the endpoint must be on the page's own origin.  The
            default transport is the scope-locked ``web.WebClient``, which follows no redirect.
  cap       at most `max_checks` posts per challenge, counted from the event ledger (``geo.check``
            records in the workdir), so the cap holds across runs and processes.  A record counts
            when it carries this challenge id OR this checker endpoint (host, port, path and any
            query parameter but ``check``), so one page posted to under several ids is one count.
            The default is 3 or the event's ``rules.wrong_answer_stop``, whichever is lower:
            whether a wrong pin costs anything is not known.  A higher cap (never above 10) needs
            `cap_note`, the player's say, and is written to the ledger (``geo.check_cap_raised``).
  repeats   a coordinate already posted for the challenge is refused, not re-sent.
  pacing    at least `min_interval_s` after the latest post for the challenge.

A refusal raises :class:`CheckRefused` and sends nothing.  A ledger that cannot be read refuses (fail
closed).  This module never chooses a coordinate and never submits to the platform: the caller names
the pin, and a returned flag goes through the submit gate (osint_geolocate.check_and_submit).
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import html as _html
import json
import math
import os
import re
import time
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable

from ctf import event as _event, flagfmt as _flagfmt, ledger as _ledger, paths as _paths, scope as _scope

DEFAULT_MAX_CHECKS = 3
MAX_CHECKS_CEILING = 10
DEFAULT_MIN_INTERVAL_S = 5.0
DEFAULT_TIMEOUT_S = 15.0
ENCODINGS = ("form", "json")
LEDGER_EVENT = "geo.check"
LEDGER_RESULT_EVENT = "geo.check_result"
LEDGER_CAP_EVENT = "geo.check_cap_raised"
MAX_CAP_NOTE = 300
LOCK_NAME = ".geo_check.lock"
MAX_PAGE_BYTES = 1 << 20
MAX_REPLY_BYTES = 64 * 1024
MAX_MESSAGE = 300
USER_AGENT = "ctf-tools-geo-checker/1"

# (method, url, body or None, headers, timeout seconds) -> (HTTP status, body bytes)
Transport = Callable[[str, str, "bytes | None", Mapping[str, str], float], "tuple[int, bytes]"]

_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}\Z")
_LAT_NAMES = ("lat", "latitude")
_LON_NAMES = ("lon", "lng", "long", "longitude")
_MAP_SIGNALS = (
    ("leaflet", re.compile(r"leaflet|\bL\.map\s*\(", re.I)),
    ("pannellum", re.compile(r"pannellum", re.I)),
    ("maplibre", re.compile(r"maplibre|mapbox-?gl", re.I)),
    ("openlayers", re.compile(r"openlayers|\bol\.Map\b", re.I)),
    ("google-maps", re.compile(r"maps\.googleapis\.com|google\.maps\.Map", re.I)),
)
_ENDPOINT_RE = re.compile(r"""["'`]([^"'`\s<>]{0,200}\?(?:[^"'`\s<>]{0,100}&)?check(?:=[^"'`\s<>&]{0,32})?)["'`]""")
_IMAGE_RE = re.compile(r"""["'`]([^"'`\s<>]{1,300}\.(?:jpe?g|png|webp))["'`]""", re.I)
_OK_KEYS = ("ok", "correct", "success", "solved")
# What says the post is form-encoded: the browser's form objects, the content type, an HTML form that
# posts, or a query string built by hand around a latitude / longitude field ('lat=' + ..., '&lng=').
_FORM_RE = re.compile(r"""FormData|URLSearchParams|x-www-form-urlencoded|<form\b[^>]*\bmethod\s*=\s*["']?post"""
                      r"""|["'`&?](?:lat|latitude|lon|lng|long|longitude)=""", re.I)


class GeoCheckError(ValueError):
    """The checker page, its endpoint or its reply is not usable, or the ledger cannot be read."""


class CheckRefused(GeoCheckError):
    """A check was refused before sending: the per-challenge cap is spent, or the coordinate repeats."""


@dataclasses.dataclass(frozen=True)
class CheckOutcome:
    challenge_id: str
    lat: float
    lon: float
    check_host: str
    http_status: int
    ok: bool | None                 # the reply's own verdict (ok / correct / success), None if it has none
    flags: tuple[str, ...]          # values in the event flag format found in the reply, as spelled
    message: str                    # the reply's message, bounded and stripped of control characters
    attempts_used: int
    attempts_left: int

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["flags"] = list(self.flags)
        return d


# --------------------------------------------------------------------------- page detection

def _first_name(text: str, names: tuple[str, ...]) -> str | None:
    """The field name of `names` the page's script uses first: quoted, as an object key or a form
    input name, or as ``name=`` in a query string built by hand ('lat=' + ..., '&lng=' + ...)."""
    best: tuple[int, str] | None = None
    for name in names:
        match = re.search(rf"""(?:["'`]{name}["'`]|\b{name}\s*:|\bname\s*=\s*["']?{name}\b|["'`&?]{name}=)""", text)
        if match is not None and (best is None or match.start() < best[0]):
            best = (match.start(), name)
    return None if best is None else best[1]


def detect_checker_page(html: str | bytes, page_url: str) -> dict[str, Any]:
    """Read a fetched challenge page for a map-pin checker.

    Returns ``{is_map_pin_page, signals, check_url, encoding, encoding_source, lat_field,
    lat_field_source, lon_field, lon_field_source, fields_source, images}``.  `signals` names the
    map / panorama libraries found (leaflet, pannellum, maplibre, openlayers, google-maps);
    `check_url` is the first quoted URL of the page with a ``check`` query parameter
    (``?check=1``), resolved against `page_url`, or None; `encoding` is ``json`` when the script
    posts ``JSON.stringify`` with a JSON content type, ``form`` when it uses FormData /
    URLSearchParams, a form content type, an HTML form that posts, or a hand-built
    ``lat=..&lon=..`` string; the field names are the first of lat / latitude and lon / lng / long
    / longitude the script uses; `images` lists the page's image URLs (the photo or panorama to
    look at).  Whatever is not found -- or, for the encoding, is found both ways -- reads form /
    lat / lon with its ``*_source`` set to "default": a guess, which
    :meth:`GeoChecker.from_page` refuses to post on.  The page is data: nothing in it is executed."""
    if isinstance(html, (bytes, bytearray)):
        text = bytes(html[:MAX_PAGE_BYTES]).decode("utf-8", errors="replace")
    elif isinstance(html, str):
        text = html[:MAX_PAGE_BYTES]
    else:
        raise GeoCheckError("page content must be text or bytes")
    signals = [name for name, pattern in _MAP_SIGNALS if pattern.search(text)]
    check_url = None
    match = _ENDPOINT_RE.search(text)
    if match is not None:
        check_url = urllib.parse.urljoin(page_url, _html.unescape(match.group(1)))
    wants_json = "JSON.stringify" in text and re.search(r"application/json", text, re.I) is not None
    wants_form = _FORM_RE.search(text) is not None
    lat_field, lon_field = _first_name(text, _LAT_NAMES), _first_name(text, _LON_NAMES)
    images = []
    for found in _IMAGE_RE.finditer(text):
        url = urllib.parse.urljoin(page_url, _html.unescape(found.group(1)))
        if url not in images:
            images.append(url)
        if len(images) >= 16:
            break
    return {
        "is_map_pin_page": bool(signals) and check_url is not None,
        "signals": signals,
        "check_url": check_url,
        "encoding": "json" if wants_json and not wants_form else "form",
        "encoding_source": "page" if wants_json != wants_form else "default",
        "lat_field": lat_field or "lat",
        "lat_field_source": "page" if lat_field else "default",
        "lon_field": lon_field or "lon",
        "lon_field_source": "page" if lon_field else "default",
        "fields_source": "page" if (lat_field and lon_field) else "default",
        "images": images,
    }


# --------------------------------------------------------------------------- the client

def _origin(url: str, what: str) -> tuple[str, str, int]:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise GeoCheckError(f"{what} is not a usable URL: {exc}") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise GeoCheckError(f"{what} must be an http(s) URL with a host; got {url!r}")
    if parts.username is not None or parts.password is not None:
        raise GeoCheckError(f"{what} must not carry credentials")
    return parts.scheme, parts.hostname.lower(), port or (443 if parts.scheme == "https" else 80)


def endpoint_key(check_url: str) -> str:
    """What identifies a checker endpoint in the ledger: ``host:port/path`` plus every query
    parameter but ``check`` (sorted), so ``/pin/?check=1`` and ``/pin?check=1`` are one endpoint and
    ``/?id=3&check=1`` and ``/?id=4&check=1`` are two."""
    _scheme, host, port = _origin(check_url, "checker endpoint")
    parts = urllib.parse.urlsplit(check_url)
    rest = sorted((k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if k != "check")
    return f"{host}:{port}{parts.path.rstrip('/') or '/'}" + ("?" + urllib.parse.urlencode(rest) if rest else "")


def _field(name: Any, what: str) -> str:
    if not isinstance(name, str) or not _FIELD_RE.match(name):
        raise GeoCheckError(f"{what} must be a plain form field name; got {name!r}")
    return name


def web_transport(page_url: str) -> Transport:
    """The default transport: the scope-locked ``web.WebClient`` for the page's origin.  Its
    constructor runs the live-service scope guard again, every request stays on that origin, and no
    redirect is followed (the checker's own reply is what is read)."""
    import web  # solvers/toolkits/web.py; imported late: it is large

    client = web.WebClient(page_url, user_agent=USER_AGENT)

    def send(method: str, url: str, body: bytes | None, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        client.timeout = timeout
        try:
            entry = client.request(method, url, data=body, headers=dict(headers), allow_redirects=False)
        except web.VPNRequired as exc:
            raise GeoCheckError(f"the checker page is not reachable: {exc}") from exc
        if entry.get("status") is None:
            raise GeoCheckError(f"the checker page gave no HTTP status for {method} {url}")
        return int(entry["status"]), bytes(entry.get("body") or b"")

    return send


class GeoChecker:
    """One challenge's map-pin checker: scope-checked on construction, capped and paced on use."""

    def __init__(self, page_url: str, challenge_id: str, *, check_url: str | None = None,
                 encoding: str = "form", lat_field: str = "lat", lon_field: str = "lon",
                 max_checks: int | None = None, cap_note: str | None = None,
                 min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
                 profile: Any = None, transport: Transport | None = None,
                 workdir: str | Path | None = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep, timeout_s: float = DEFAULT_TIMEOUT_S):
        cid = str(challenge_id).strip() if isinstance(challenge_id, (str, int)) else ""
        if not cid or len(cid) > 256 or any(ord(ch) < 0x20 for ch in cid):
            raise GeoCheckError("challenge id must be a short non-empty id")
        self.challenge_id = cid
        if not isinstance(page_url, str):
            raise GeoCheckError("page URL must be text")
        self.page_url = page_url.strip()
        self._page_origin = _origin(self.page_url, "page URL")
        # The live-service scope guard: opens no connection, resolves no name, refuses a host outside
        # the event profile's rules.live_service_scope and the event platform itself.
        _scope.check_url(self.page_url, what=f"geo checker page {self.page_url!r}", profile=profile)
        if profile is not None:
            self.profile = profile
        else:                   # the flag format is the current event's; the guard above proved one loads
            try:
                self.profile = _event.current()
            except _event.EventError:
                self.profile = _scope.pinned()
        # The default cap is never above the event's own stop for wrong answers on one challenge.
        self.default_checks = max(1, min(DEFAULT_MAX_CHECKS, int(self.profile.rules.wrong_answer_stop)))
        if max_checks is None:
            max_checks = self.default_checks
        if isinstance(max_checks, bool) or not isinstance(max_checks, int) or not 1 <= max_checks <= MAX_CHECKS_CEILING:
            raise GeoCheckError(f"max_checks must be 1..{MAX_CHECKS_CEILING} (a wrong pin may cost points)")
        note = " ".join(cap_note.split()) if isinstance(cap_note, str) else ""
        if cap_note is not None and (not note or len(note) > MAX_CAP_NOTE or not note.isprintable()):
            raise GeoCheckError(f"cap_note must be 1..{MAX_CAP_NOTE} printable characters")
        if max_checks > self.default_checks and not note:
            raise GeoCheckError(f"max_checks={max_checks} is above this event's default of {self.default_checks}: "
                                "raising the cap needs cap_note (--cap-note), the player's say in a few "
                                "words; it is written to the ledger")
        self.max_checks, self.cap_note = max_checks, note
        self.min_interval_s = float(min_interval_s)
        if not math.isfinite(self.min_interval_s) or self.min_interval_s < 0:
            raise GeoCheckError("min_interval_s must be a non-negative number of seconds")
        self.timeout_s = float(timeout_s)
        if not 0 < self.timeout_s <= 120:
            raise GeoCheckError("timeout_s must be in 0..120 seconds")
        self._transport = transport
        self._workdir = None if workdir is None else Path(workdir)
        self._clock, self._sleep = clock, sleep
        self.detection: dict[str, Any] | None = None
        self.check_url = self.endpoint = ""
        self.encoding, self.lat_field, self.lon_field = "form", "lat", "lon"
        self._configure(check_url, encoding, lat_field, lon_field)

    def _configure(self, check_url: str | None, encoding: str, lat_field: str, lon_field: str) -> None:
        if check_url is None:
            parts = urllib.parse.urlsplit(self.page_url)
            check_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "check=1", ""))
        if _origin(check_url, "checker endpoint") != self._page_origin:
            raise GeoCheckError(f"checker endpoint {check_url!r} is not on the page's origin "
                                f"({self._page_origin[0]}://{self._page_origin[1]}:{self._page_origin[2]}); "
                                "a pin is only ever posted to the page it came from")
        if encoding not in ENCODINGS:
            raise GeoCheckError(f"encoding must be one of {', '.join(ENCODINGS)}; got {encoding!r}")
        self.check_url, self.encoding, self.endpoint = check_url, encoding, endpoint_key(check_url)
        self.lat_field, self.lon_field = _field(lat_field, "lat_field"), _field(lon_field, "lon_field")
        if self.lat_field == self.lon_field:
            raise GeoCheckError("lat_field and lon_field must differ")

    @classmethod
    def from_page(cls, page_url: str, challenge_id: str, *, encoding: str | None = None,
                  lat_field: str | None = None, lon_field: str | None = None, **kwargs: Any) -> "GeoChecker":
        """Fetch the page once (a GET; it is not a check and does not count against the cap), read
        it with :func:`detect_checker_page` and build the checker from what it says.  A page with no
        checker endpoint is an error, never a guessed ``?check=1``; explicit `encoding` / field names
        override the page's.  A field name or an encoding that the page does not show and the caller
        did not name is an error too: a post with guessed names would spend a capped attempt on a
        request the checker cannot read."""
        self = cls(page_url, challenge_id, **kwargs)
        status, body = self._send("GET", self.page_url, None, {})
        if status != 200:
            raise GeoCheckError(f"the challenge page answered HTTP {status}; cannot read it for a checker")
        found = detect_checker_page(body, self.page_url)
        if found["check_url"] is None:
            raise GeoCheckError("the page shows no checker endpoint (no quoted URL with a `check` query "
                                "parameter); if it is a map-pin page, name the endpoint with check_url")
        self._configure(found["check_url"], encoding or found["encoding"],
                        lat_field or found["lat_field"], lon_field or found["lon_field"])
        unknown = [what for what, named, source in (
            ("the latitude field name (lat_field, --lat-field)", lat_field, found["lat_field_source"]),
            ("the longitude field name (lon_field, --lon-field)", lon_field, found["lon_field_source"]),
            ("the post encoding (encoding, --encoding form|json)", encoding, found["encoding_source"]),
        ) if named is None and source != "page"]
        if unknown:
            raise GeoCheckError("the page does not show " + ", ".join(unknown) + "; nothing is posted on a "
                                "guess (it would spend one of the capped attempts): read the page's script "
                                "and name what is missing")
        self.detection = found
        return self

    # ---- plumbing

    def _send(self, method: str, url: str, body: bytes | None, headers: Mapping[str, str]) -> tuple[int, bytes]:
        if self._transport is None:
            self._transport = web_transport(self.page_url)
        reply = self._transport(method, url, body, headers, self.timeout_s)
        if (not isinstance(reply, tuple) or len(reply) != 2 or isinstance(reply[0], bool)
                or not isinstance(reply[0], int) or not isinstance(reply[1], (bytes, bytearray))):
            raise GeoCheckError("checker transport must return (status, body bytes)")
        return reply[0], bytes(reply[1])

    def _dir(self) -> Path:
        return _paths.workdir() if self._workdir is None else self._workdir

    @contextlib.contextmanager
    def _locked(self):
        folder = self._dir()
        folder.mkdir(parents=True, exist_ok=True)
        fd = os.open(folder / LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def history(self) -> list[dict[str, Any]]:
        """The ``geo.check`` ledger records that count against this checker, oldest first: those of
        this challenge id and those posted to this endpoint under any id.  An unreadable ledger
        raises GeoCheckError: with the count unknown, nothing is sent."""
        try:
            return [rec for rec in _ledger.read(self._dir())
                    if rec.get("event") == LEDGER_EVENT
                    and (str(rec.get("challenge_id")) == self.challenge_id or rec.get("endpoint") == self.endpoint)]
        except (ValueError, OSError) as exc:
            raise GeoCheckError(f"cannot count earlier checks for challenge {self.challenge_id}: the event "
                                f"ledger is unreadable ({exc}); refusing to post") from exc

    def attempts_left(self) -> int:
        return max(0, self.max_checks - len(self.history()))

    # ---- the one call that posts

    def check(self, lat: float, lon: float) -> CheckOutcome:
        """Post one named coordinate to the checker and read the reply.

        Raises CheckRefused (nothing sent) when the challenge's cap is spent or the coordinate was
        already posted.  The attempt is written to the ledger before the request, so a post that
        dies half-way still counts; a cap above the event's default is written too, once, with its
        note.  Flags are every value of the event flag format in the reply,
        spelled exactly as the page returned them."""
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in (lat, lon)):
            raise GeoCheckError("lat and lon must be finite numbers")
        lat, lon = float(lat), float(lon)
        if not -90 <= lat <= 90 or not -180 <= lon <= 180:
            raise GeoCheckError("the coordinate is outside Earth bounds")
        key = f"{lat:.6f},{lon:.6f}"
        with self._locked():
            past = self.history()
            if any(rec.get("coordinate") == key for rec in past):
                raise CheckRefused(f"{key} was already posted to the checker for challenge "
                                   f"{self.challenge_id}; a repeat would only spend an attempt")
            if len(past) >= self.max_checks:
                raise CheckRefused(f"challenge {self.challenge_id} (checker {self.endpoint}) has used "
                                   f"{len(past)} of {self.max_checks} checker posts; raise max_checks (ceiling "
                                   f"{MAX_CHECKS_CEILING}) only on the player's say, with cap_note: whether a "
                                   "wrong pin costs points is not known")
            sent_times = [rec["sent_at"] for rec in past if isinstance(rec.get("sent_at"), (int, float))]
            if sent_times:
                wait = max(sent_times) + self.min_interval_s - self._clock()
                if wait > 0:
                    self._sleep(wait)
            attempt = len(past) + 1
            if self.max_checks > self.default_checks and not any(
                    rec.get("event") == LEDGER_CAP_EVENT and rec.get("endpoint") == self.endpoint
                    and str(rec.get("challenge_id")) == self.challenge_id and rec.get("max_checks") == self.max_checks
                    for rec in _ledger.read(self._dir())):
                _ledger.append(LEDGER_CAP_EVENT, workdir=self._dir(), challenge_id=self.challenge_id,
                               endpoint=self.endpoint, max_checks=self.max_checks,
                               default_checks=self.default_checks, note=self.cap_note)
            _ledger.append(LEDGER_EVENT, workdir=self._dir(), challenge_id=self.challenge_id, coordinate=key,
                           host=self._page_origin[1], endpoint=self.endpoint, sent_at=self._clock(),
                           attempt=attempt, of=self.max_checks)
        fields = {self.lat_field: lat, self.lon_field: lon}
        if self.encoding == "json":
            body = json.dumps(fields).encode("utf-8")
            content_type = "application/json"
        else:
            body = urllib.parse.urlencode({k: repr(v) for k, v in fields.items()}).encode("ascii")
            content_type = "application/x-www-form-urlencoded"
        status, raw = self._send("POST", self.check_url, body,
                                 {"Content-Type": content_type, "Accept": "application/json"})
        if len(raw) > MAX_REPLY_BYTES:
            raise GeoCheckError(f"the checker's reply is larger than {MAX_REPLY_BYTES} bytes; not read")
        text = raw.decode("utf-8", errors="replace")
        ok: bool | None = None
        message = text
        try:
            reply = json.loads(text)
        except ValueError:
            reply = None
        if isinstance(reply, Mapping):
            for name in _OK_KEYS:
                if isinstance(reply.get(name), bool):
                    ok = reply[name]
                    break
            if isinstance(reply.get("message"), str):
                message = reply["message"]
            text = "\n".join(_strings(reply))
        flags = tuple(dict.fromkeys(_flagfmt.for_profile(self.profile).find_flags(text)))
        if ok is None and flags:
            ok = True
        digest = hashlib.sha256(flags[0].encode("utf-8")).hexdigest()[:12] if flags else None
        _ledger.append(LEDGER_RESULT_EVENT, workdir=self._dir(), challenge_id=self.challenge_id, coordinate=key,
                       http_status=status, ok=ok, flag_found=bool(flags), flag_sha256=digest)
        clean = "".join(ch if ch.isprintable() else " " for ch in message).strip()[:MAX_MESSAGE]
        return CheckOutcome(self.challenge_id, lat, lon, self._page_origin[1], status, ok, flags, clean,
                            attempts_used=attempt, attempts_left=max(0, self.max_checks - attempt))


def _strings(value: Any, depth: int = 0) -> list[str]:
    """Every string in a decoded JSON reply (values and keys), bounded in depth."""
    if depth > 8:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        out = []
        for key, item in value.items():
            out.append(str(key))
            out.extend(_strings(item, depth + 1))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_strings(item, depth + 1))
        return out
    return []


__all__ = ["GeoChecker", "GeoCheckError", "CheckRefused", "CheckOutcome", "detect_checker_page",
           "endpoint_key", "web_transport", "DEFAULT_MAX_CHECKS", "MAX_CHECKS_CEILING", "ENCODINGS"]
