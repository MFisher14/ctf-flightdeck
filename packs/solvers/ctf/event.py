"""Event profiles: events/<slug>/event.toml, the single per-event source of truth.

    from ctf import event
    prof = event.load("csctf")        # EventProfile, validated
    prof = event.current()            # $CTF_EVENT, else the only profile under events/
    event.available()                 # slugs that have an event.toml

Schema (docs/CONTRACTS.md has the annotated version). Unknown keys anywhere are an error, every
enum is checked, and a missing required key names itself; nothing defaults silently except the
defaults written below.

    slug = "csctf"                    # must equal the folder name
    name = "CSCTF 2026"
    categories = ["Web", ...]         # default []
    sectors = ["energy", ...]         # default []
    dates = { start = 2026-11-06T13:00:00Z, end = 2026-11-08T13:00:00Z }

    [platform]  kind = "ctfd" | "gamemaster" | "manual";  base_url (required unless manual);  team;
                hosts = [host names] (default []: other names of the platform, such as a proxy)
    [flag]      prefixes = [..] ([] = unknown, any word prefix);  body = regex (default below);
                case = "exact" | "prefix-insensitive" | "insensitive"
    [proof]     optional: pattern = regex;  case
    [rules]     submit_mode = "auto" | "confirm" | "manual";  wrong_answer_stop = 3;  guess_budget = 0;
                hints_allowed = false;  flag_sharing = "allowed" | "forbidden";
                ai_on_platform = "allowed" | "forbidden";  live_service_scope = [host globs];
                public_fetch_allow = [host globs];  web_state_changing = false;
                wrong_penalty = points (optional: not known);  approved_extras = true;
                hint_suggestions = false;  pointed_services = "allowed" | "forbidden" (default forbidden);
                chain_rpc = "allowed" | "forbidden" (default forbidden; B-243: read-only EVM JSON-RPC
                to an in-scope node, solvers/toolkits/evm_rpc.py)
                sandboxed_execution = "allowed" | "forbidden" (default forbidden; B-242)
    [writeups]  redact_flags = true;  public_repo = "" (none);  publish_hold = true (B-098)
    [budget]    per_point = 0.5;  floor = 25.0;  ceiling = 250.0;  per_challenge_day (optional);
                overthink_usd / overthink_max_points / overthink_min_solves (optional, all three; B-130)
    [human]     optional (B-169): confirm_system = "" (an off-platform points system the player
                confirms by hand, e.g. "CourseStack"; none by default);  checklist = [event-specific
                human-only items for the evening checklist]
    [discord]   optional (B-112): capture = "forbidden" | "bot" (default forbidden: no API client; only
                what the player pastes or exports is analysed);  api_base = "https://discord.com/api/v10";
                token_env = "CTF_DISCORD_TOKEN" (the NAME of the variable holding the bot token, never
                the token);  guild_id = "" (the server's numeric id; none by default)
    [submit]    per_minute = 10;  interval_s = 1.0;  per_challenge_interval_s = 3.0;  max_hold_s = 600.0;
                rotating_miss_budget = 6
                (the cross-process submit queue, ctf/platform/queue.py, B-006)
    [sweep]     mode = "forbidden" | "player-authorized" (default forbidden);  max_count = 50;
                interval_s = 5.0;  ttl_s = 3600.0
                (player-authorized sweeps, ctf/eventpolicy.py, B-173)
    [models]    optional (B-100): primary = "claude-opus-5-5";  fallback = ["claude-opus-4-8"];
                cyber_verified = "unknown" | "requested" | "granted" | "denied" (default "unknown");
                docs = "claude-sonnet-5-5";  docs_on_primary = ["pwn"] (B-097: ctf/writeup/assist.py)
    [allowance] optional (B-171): margin_pct = 10.0;  reserve_pct = 20.0;  build_ceiling_pct = 70.0;
                recheck_minutes = 30.0;  releases = [datetimes];  daily_release = "HH:MM" ("" none);
                tz = "UTC";  daily_usd = 0.0 (none)   (harness quota reserve and scheduling, ctf/quota.py)
    [instances] optional (B-003): the per-team container plugin. cap = N | null (local slot cap);
                [instances.endpoints] = { plugin = "docker_per_team" | "ctfd_docker", ... } (any extra
                key overrides that shape, or give all of spawn/stop/renew/status explicitly). Validated
                at load by ctf.instances.endpoints_from_config. No section => this event has no plugin.
    [routing]   optional (B-201, ctf/router.py): default_difficulty = "medium";  verify_candidate = "";
                top_categories = [];  [[routing.route]] = { role = "*", difficulty = "*", harness = "*",
                model, effort, tier = "default", budget_usd } (structure checked here; every model,
                harness and tier is checked against tools/ledger/pricing.json by ctf.router.Router)
    [wire]      optional (B-140): per_minute = 0;  release_budget = 0;  reserve = 0;
                release_window_s = 60.0;  release_poll_free_s = 10.0;  release_poll_gap_s = 0.0;
                release_lane_budget = 0;  release_lanes = {lane = n};  pause_s = 20.0;
                pause_max_s = 120.0;  max_wait_s = 30.0
                (the per-request journal and request budget, ctf/platform/wire.py; 0 = no cap)

Cross-field rules (enforced): platform kind "manual" or ai_on_platform "forbidden" => submit_mode
"manual"; submit_mode "auto" needs known flag prefixes; budget floor <= ceiling; models.primary is
not one of models.fallback; flag_sharing "forbidden" => writeups.redact_flags true; sweep.mode
"player-authorized" needs a submit_mode other than "manual"; allowance margin_pct + reserve_pct < 100.
"""
from __future__ import annotations

import datetime as _dt
import re
import tomllib
import zoneinfo
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from . import env, paths

PROFILE_NAME = "event.toml"
DEFAULT_BODY = r"[^{}\s]{1,256}"

PLATFORM_KINDS = ("ctfd", "gamemaster", "manual")
SUBMIT_MODES = ("auto", "confirm", "manual")
CASE_RULES = ("exact", "prefix-insensitive", "insensitive")
ALLOWED_FORBIDDEN = ("allowed", "forbidden")
SWEEP_MODES = ("forbidden", "player-authorized")
CYBER_VERIFIED = ("unknown", "requested", "granted", "denied")
# B-112: Discord recon. "forbidden": no API client at all. "bot": the player has checked that the event
# rules and Discord's terms allow the team's bot application and an organizer admitted it to the server.
DISCORD_CAPTURE = ("forbidden", "bot")
DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_TOKEN_ENV = "CTF_DISCORD_TOKEN"
_ENV_NAME_RE = re.compile(r"^CTF_[A-Z0-9_]{1,60}$")
_SNOWFLAKE_RE = re.compile(r"^[0-9]{5,25}$")
# B-095: reasoning-effort tiers, cheapest first. Solvers launch at the profile default (medium) and
# the escalation ladder (ctf.escalation) ramps up a tier at a time by starting a fresh agent, never a
# mid-session change (a top-level effort change rewrites the prompt cache, ~$0.32/rewrite).
EFFORT_LEVELS = ("minimal", "low", "medium", "high", "max")
# B-201: the [routing] table's keys (ctf/router.py). Roles are the spend categories the launchers
# record (ctf.stages.SPEND_CATEGORIES); difficulties are cheapest first; "*" matches any.
ROUTE_DIFFICULTIES = ("warmup", "easy", "medium", "hard")
ROUTE_HARNESSES = ("claude", "codex")
ROUTE_ANY = "*"
DEFAULT_TIER = "default"
_TIER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_MODEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_PREFIX_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")


class EventError(ValueError):
    """A profile is missing, ambiguous or invalid. The message names the file and key."""


# ---------------------------------------------------------------------------------------- dataclasses

@dataclass(frozen=True)
class Platform:
    kind: str
    base_url: str | None = None
    team: str | None = None
    hosts: tuple[str, ...] = ()          # other platform host names (a proxy); never a target

    def all_hosts(self) -> frozenset[str]:
        """Every host name that is the platform: base_url's host plus `hosts`, lowercased."""
        from urllib.parse import urlsplit
        found = {h.lower() for h in self.hosts}
        if self.base_url:
            found.add((urlsplit(self.base_url).hostname or "").lower())
        found.discard("")
        return frozenset(found)


@dataclass(frozen=True)
class FlagSpec:
    prefixes: tuple[str, ...]
    body: str = DEFAULT_BODY
    case: str = "exact"

    @property
    def known(self) -> bool:
        return bool(self.prefixes)


@dataclass(frozen=True)
class ProofSpec:
    pattern: str
    case: str = "exact"


@dataclass(frozen=True)
class Rules:
    submit_mode: str
    flag_sharing: str
    ai_on_platform: str
    wrong_answer_stop: int = 3
    guess_budget: int = 0
    hints_allowed: bool = False
    live_service_scope: tuple[str, ...] = ()
    web_state_changing: bool = False
    # Public third-party hosts (symbol servers, package mirrors, tunnel services) a tool may fetch
    # from. Not challenge targets: ctf.scope.check_public_fetch reads it (R-13). Default: none.
    public_fetch_allow: tuple[str, ...] = ()
    # B-173 policy fields. Points lost per judged-incorrect answer; None = the profile does not say
    # (the agent rules then treat every wrong answer as costly).
    wrong_penalty: int | None = None
    # May the player approve sends past wrong_answer_stop (`ctf submit-queue approve`)? False makes
    # the stop final for the challenge (ctf/platform/rules.py).
    approved_extras: bool = True
    # May agents suggest taking a hint to the player? Taking one is always the player's decision.
    hint_suggestions: bool = False
    # "allowed": a challenge service the player points at (`ctf policy point`) may be contacted
    # though live_service_scope does not list it (ctf/scope.py). The platform never is.
    pointed_services: str = "forbidden"
    # B-243. "allowed": the read-only EVM JSON-RPC reader (solvers/toolkits/evm_rpc.py) may query a chain
    # node, and only one whose URL live_service_scope admits, and only read methods. Default: no chain reads.
    chain_rpc: str = "forbidden"
    # B-242. "allowed": the runtime adapters (binary.runtime_trace) may run a delivered managed or
    # bytecode artifact for a bounded trace, only inside a pinned container with no network and no
    # host mount (tools/sandbox.py runtime_run). "forbidden" (the default): no delivered artifact is
    # run by the master, and the engine reports `blocked` naming this key.
    sandboxed_execution: str = "forbidden"


@dataclass(frozen=True)
class Writeups:
    redact_flags: bool = True
    public_repo: str | None = None
    publish_hold: bool = True     # nothing is published until the player clears it (ctf.writeup.publish)


@dataclass(frozen=True)
class Budget:
    per_point: float = 0.5
    floor: float = 25.0
    ceiling: float = 250.0
    per_challenge_day: float | None = None
    # B-130 overthink cap: a low-point, HIGH-SOLVE challenge (easy, many teams already solved it) is
    # not worth a deep token spend. When all three are set AND a challenge is at or below
    # overthink_max_points and at least overthink_min_solves teams have solved it, its cap is clamped
    # down to overthink_usd. Disabled (no clamp) unless all three are set and the solve count is known.
    overthink_usd: float | None = None
    overthink_max_points: float | None = None
    overthink_min_solves: int | None = None


@dataclass(frozen=True)
class Human:
    """Human-only work the evening checklist and confirm list surface (B-169, ctf.humanops)."""
    confirm_system: str | None = None
    checklist: tuple[str, ...] = ()


@dataclass(frozen=True)
class Discord:
    """Discord recon for announcement and recognition flags (B-112, ctf.discordrecon, ctf.discordapi).
    `capture` is the player's recorded clearance for the API client: "forbidden" (the default) means
    only material the player pastes or exports is analysed. The token itself is never in the profile:
    `token_env` names the environment variable that holds it."""
    capture: str = "forbidden"
    api_base: str = DISCORD_API_BASE
    token_env: str = DISCORD_TOKEN_ENV
    guild_id: str | None = None


@dataclass(frozen=True)
class SubmitPace:
    """The team's submit queue (ctf/platform/queue.py): every process of this event shares it."""
    per_minute: int = 10                  # sends in any 60 s window, team-wide (all processes)
    interval_s: float = 1.0               # at least this long between any two sends
    per_challenge_interval_s: float = 3.0  # at least this long between two sends on one challenge
    max_hold_s: float = 600.0             # one submit call retries an unjudged answer this long, then
                                          # leaves it queued for `ctf submit-queue drain`
    rotating_miss_budget: int = 6         # rotating-flag misses (ctf.dynamic) per challenge that do not
                                          # count as wrong answers; each miss past it counts toward
                                          # rules.wrong_answer_stop (ctf/platform/rules.py)


@dataclass(frozen=True)
class WirePace:
    """B-140: the platform request budget every process of this event shares (ctf/platform/wire.py).
    Every request is journaled whatever these say; a 0 cap is no cap (journal only)."""
    per_minute: int = 0                   # requests in any 60 s window, team-wide; 0 = no cap
    release_budget: int = 0               # requests from a release anchor to the end of its window; 0 = none
    reserve: int = 0                      # of each cap, kept for submits and attempt starts
    release_window_s: float = 60.0        # the release window: this long from each release anchor
    release_poll_free_s: float = 10.0     # list polls are not spread for this long after the anchor
    release_poll_gap_s: float = 0.0       # then, to the window's end, list polls this far apart; 0 = off
    release_lane_budget: int = 0          # per lane (CTF_WIRE_LANE) in the window: its reads held past it; 0 = none
    release_lanes: tuple[tuple[str, int], ...] = ()   # per-lane overrides of release_lane_budget
    pause_s: float = 20.0                 # a 429 with no Retry-After pauses every process this long,
    pause_max_s: float = 120.0            # doubling on a repeat within 120 s, up to this
    max_wait_s: float = 30.0              # release/poll-gap/lane holds end after this (forced); never per_minute

    def lane_budget(self, lane: str | None) -> int:
        """The release-window budget of `lane`; 0 (none) for an unlabelled request."""
        if not lane:
            return 0
        return dict(self.release_lanes).get(lane, self.release_lane_budget)


@dataclass(frozen=True)
class SweepPolicy:
    """Player-authorized sweeps (ctf/eventpolicy.py, B-173): the guard stays on by default; the
    player authorizes one sweep run of at most max_count sends on one challenge."""
    mode: str = "forbidden"               # "forbidden" | "player-authorized"
    max_count: int = 50                   # most sends one authorization may grant
    interval_s: float = 5.0               # the sweep pacer: seconds between two sweep sends
    ttl_s: float = 3600.0                 # an authorization expires this long after it is granted

    @property
    def authorized(self) -> bool:
        return self.mode == "player-authorized"


@dataclass(frozen=True)
class Models:
    """B-100: the model sanctioned work should run on, the models a safety classifier may move a
    session onto, and the status of the player's cyber verified profile (BUILD-PLAN O-3). Only
    "granted" means the fallback is not expected; the default "unknown" is reported, never assumed."""
    primary: str = "claude-opus-5-5"
    fallback: tuple[str, ...] = ("claude-opus-4-8",)
    cyber_verified: str = "unknown"
    # B-097: doc drafts (writeups, retros) run on `docs`; the one review pass on published text, retro
    # recommendations and the writeups of `docs_on_primary` categories (exploit-heavy work the docs
    # model's own classifier may refuse; matched case-insensitively) run on `primary`.
    docs: str = "claude-sonnet-5-5"
    docs_on_primary: tuple[str, ...] = ("pwn",)
    # B-095: the reasoning effort a solver's first agent launches at. The escalation ladder ramps up
    # from here (medium -> high -> max) by starting a fresh agent, so the base stays cheap.
    effort: str = "medium"

    @property
    def verified(self) -> bool:
        return self.cyber_verified == "granted"


@dataclass(frozen=True)
class RouteRule:
    """B-201: one [[routing.route]] entry. `role`, `difficulty` and `harness` select (ROUTE_ANY = any);
    `model` (with its speed `tier` and `budget_usd`) and `effort` are what it routes to, either may be
    left out (None: a less specific rule or the router's built-in default supplies it). A tier other
    than DEFAULT_TIER needs an explicit `budget_usd` (B-033); `index` is its place in the file."""
    role: str = ROUTE_ANY
    difficulty: str = ROUTE_ANY
    harness: str = ROUTE_ANY
    model: str | None = None
    effort: str | None = None
    tier: str = DEFAULT_TIER
    budget_usd: float | None = None
    index: int = 0

    @property
    def specificity(self) -> int:
        return (4 * (self.harness != ROUTE_ANY) + 2 * (self.role != ROUTE_ANY)
                + (self.difficulty != ROUTE_ANY))


@dataclass(frozen=True)
class Routing:
    """B-201: the optional [routing] table. None on the profile means the event has not opted in: the
    launchers and `ctf escalate` then behave as before (B-095 effort, [models] roster)."""
    rules: tuple[RouteRule, ...] = ()
    default_difficulty: str = "medium"
    verify_candidate: str | None = None       # B-096: verify moves here only after an approving A/B
    top_categories: tuple[str, ...] = ()      # lowercased; non-empty: only these route solve at "hard"


@dataclass(frozen=True)
class Allowance:
    """B-171: how much of each harness quota window (Claude Code, Codex) work may use, and when releases
    fall (ctf/quota.py). Percentages are of a window (the 5-hour session, the week). A quota reading is
    not fully trusted (one was wrong in the PINK+ logs), so every reading counts margin_pct higher."""
    margin_pct: float = 10.0              # added to every reading: the meter is not trusted to the percent
    reserve_pct: float = 20.0             # held back from solve and build work in a window that outlives
                                          # the next release, so release work is funded
    build_ceiling_pct: float = 70.0       # build sessions stop at this much of a window
    recheck_minutes: float = 30.0         # a limit-hit message is re-probed after this long, whatever reset
                                          # time it named (Codex said out for days and ran 11 min later)
    releases: tuple[_dt.datetime, ...] = ()   # wave or release times (aware; a naive one is in tz)
    daily_release: str = ""               # "HH:MM" in tz: a release every day of the event; "" none
    tz: str = "UTC"                       # IANA zone for daily_release, naive releases and per-day totals
    daily_usd: float = 0.0                # per-day spend allowance for the per-day ledger; 0 = none


@dataclass(frozen=True)
class InstancesCfg:
    """B-003: the per-team container-instance plugin for this event. `cap` is the local slot cap the
    scheduler honours (None = no local cap; the plugin's own limit still applies). `endpoints` is the
    raw plugin wiring, already validated by `ctf.instances.endpoints_from_config` at profile load, and
    handed straight to `ctf.instances.Instances.from_config`. `endpoints` is stored as a read-only deep
    copy (tables -> MappingProxyType, arrays -> tuples), so the parsed TOML or a caller's dict is never
    aliased and nothing can change the wiring after it was validated. It is excluded from the hash (so
    a frozen `EventProfile` stays hashable) but kept in equality."""
    cap: int | None
    endpoints: Mapping[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self):
        object.__setattr__(self, "endpoints", _freeze(self.endpoints))

    def as_config(self) -> dict:
        """The mapping `ctfd.make_adapter(profile, instances=...)` / `Instances.from_config` expect: a
        fresh plain-dict copy on every call (mutating it does not touch the profile)."""
        return {"cap": self.cap, "endpoints": _thaw(self.endpoints)}


def _freeze(v: Any) -> Any:
    """A deep read-only copy of parsed TOML: tables -> MappingProxyType, arrays -> tuples."""
    if isinstance(v, Mapping):
        return MappingProxyType({str(k): _freeze(x) for k, x in v.items()})
    if isinstance(v, (list, tuple)):
        return tuple(_freeze(x) for x in v)
    return v


def _thaw(v: Any) -> Any:
    """The inverse of _freeze: newly built plain dicts and lists."""
    if isinstance(v, Mapping):
        return {k: _thaw(x) for k, x in v.items()}
    if isinstance(v, tuple):
        return [_thaw(x) for x in v]
    return v


@dataclass(frozen=True)
class EventProfile:
    slug: str
    name: str
    start: _dt.date | _dt.datetime
    end: _dt.date | _dt.datetime
    platform: Platform
    flag: FlagSpec
    rules: Rules
    proof: ProofSpec | None = None
    writeups: Writeups = field(default_factory=Writeups)
    budget: Budget = field(default_factory=Budget)
    human: Human = field(default_factory=Human)
    discord: Discord = field(default_factory=Discord)
    submit: SubmitPace = field(default_factory=SubmitPace)
    sweep: SweepPolicy = field(default_factory=SweepPolicy)
    models: Models = field(default_factory=Models)
    allowance: Allowance = field(default_factory=Allowance)
    instances: InstancesCfg | None = None
    wire: WirePace = field(default_factory=WirePace)
    routing: Routing | None = None
    categories: tuple[str, ...] = ()
    sectors: tuple[str, ...] = ()
    path: Path | None = None

    @property
    def manual(self) -> bool:
        return self.platform.kind == "manual" or self.rules.submit_mode == "manual"


# ---------------------------------------------------------------------------------------- validation

class _Reader:
    """Pops keys from one TOML table with type checks; finish() rejects whatever is left."""

    def __init__(self, src: str, where: str, table: Any):
        if not isinstance(table, dict):
            raise EventError(f"{src}: [{where}] must be a table")
        self.src, self.where, self.t = src, where, dict(table)

    def _name(self, key: str) -> str:
        return f"{self.where}.{key}" if self.where else key

    def _fail(self, key: str, msg: str) -> EventError:
        return EventError(f"{self.src}: {self._name(key)} {msg}")

    _MISSING = object()

    def get(self, key: str, types: type | tuple, default: Any = _MISSING) -> Any:
        if key not in self.t:
            if default is self._MISSING:
                raise self._fail(key, "is required")
            return default
        v = self.t.pop(key)
        # bool is an int subclass: never accept a bool where a number is asked, or vice versa.
        tt = types if isinstance(types, tuple) else (types,)
        if isinstance(v, bool) and bool not in tt:
            raise self._fail(key, f"must be {self._tn(tt)}, got a boolean")
        if not isinstance(v, tt):
            raise self._fail(key, f"must be {self._tn(tt)}, got {type(v).__name__}")
        return v

    @staticmethod
    def _tn(tt: tuple) -> str:
        return " or ".join(t.__name__ for t in tt)

    def enum(self, key: str, choices: tuple[str, ...], default: Any = _MISSING) -> str:
        v = self.get(key, str, default)
        if v not in choices:
            raise self._fail(key, f"must be one of {', '.join(choices)}; got {v!r}")
        return v

    def strlist(self, key: str, default: Any = _MISSING) -> tuple[str, ...]:
        v = self.get(key, list, default)
        if not all(isinstance(x, str) and x for x in v):
            raise self._fail(key, "must be a list of non-empty strings")
        return tuple(v)

    def number(self, key: str, default: Any = _MISSING) -> float:
        v = self.get(key, (int, float), default)
        return float(v) if v is not None else None

    def table(self, key: str, required: bool = True) -> "_Reader | None":
        if key not in self.t:
            if required:
                raise self._fail(key, "table is required")
            return None
        return _Reader(self.src, self._name(key), self.t.pop(key))

    def finish(self) -> None:
        if self.t:
            names = ", ".join(sorted(self._name(k) for k in self.t))
            raise EventError(f"{self.src}: unknown key(s): {names}")


def _when(r: _Reader, key: str) -> _dt.date | _dt.datetime:
    v = r.get(key, (_dt.date, _dt.datetime, str))
    if isinstance(v, str):
        try:
            v = _dt.datetime.fromisoformat(v) if "T" in v else _dt.date.fromisoformat(v)
        except ValueError:
            raise r._fail(key, f"is not an ISO date/datetime: {v!r}") from None
    if isinstance(v, _dt.time):
        raise r._fail(key, "must be a date or datetime, not a bare time")
    return v


def _regex(r: _Reader, key: str, value: str) -> str:
    if not value.isascii():
        raise r._fail(key, "must be ASCII (it is also compiled as a bytes pattern)")
    try:
        re.compile(value)
    except re.error as e:
        raise r._fail(key, f"is not a valid regex: {e}") from None
    return value


def parse(data: dict, *, src: str = "<profile>", expect_slug: str | None = None) -> EventProfile:
    """Validate a decoded TOML mapping into an EventProfile."""
    top = _Reader(src, "", data)
    slug = top.get("slug", str)
    if not _SLUG_RE.match(slug):
        raise top._fail("slug", f"must match {_SLUG_RE.pattern}; got {slug!r}")
    if expect_slug is not None and slug != expect_slug:
        raise top._fail("slug", f"is {slug!r} but the profile lives in events/{expect_slug}/")
    name = top.get("name", str)
    categories = top.strlist("categories", [])
    sectors = top.strlist("sectors", [])

    d = top.table("dates")
    start, end = _when(d, "start"), _when(d, "end")
    d.finish()
    if type(start) is type(end) and end < start:
        raise EventError(f"{src}: dates.end is before dates.start")

    p = top.table("platform")
    kind = p.enum("kind", PLATFORM_KINDS)
    base_url = p.get("base_url", str, None)
    team = p.get("team", (str, int), None)
    hosts = p.strlist("hosts", [])
    p.finish()
    for h in hosts:
        if not _HOST_RE.fullmatch(h):
            raise EventError(f"{src}: platform.hosts entry {h!r} is not a bare host name "
                             "(no scheme, port, path or spaces)")
    if kind != "manual" and not base_url:
        raise EventError(f"{src}: platform.base_url is required for kind {kind!r}")
    if base_url and not re.match(r"^https?://", base_url):
        raise EventError(f"{src}: platform.base_url must start with http:// or https://")
    platform = Platform(kind=kind, base_url=base_url.rstrip("/") if base_url else None,
                        team=str(team) if team is not None else None, hosts=hosts)

    f = top.table("flag")
    prefixes = f.strlist("prefixes")
    for pre in prefixes:
        if not _PREFIX_RE.match(pre):
            raise f._fail("prefixes", f"entry {pre!r} must match {_PREFIX_RE.pattern}")
    body = _regex(f, "body", f.get("body", str, DEFAULT_BODY))
    if re.fullmatch(body, "}") or re.fullmatch(body, "a}b"):
        raise f._fail("body", "must not be able to match '}' (it would run past the closing brace)")
    case = f.enum("case", CASE_RULES, "exact")
    f.finish()
    flag = FlagSpec(prefixes=prefixes, body=body, case=case)

    proof = None
    pr = top.table("proof", required=False)
    if pr is not None:
        proof = ProofSpec(pattern=_regex(pr, "pattern", pr.get("pattern", str)),
                          case=pr.enum("case", CASE_RULES, "exact"))
        pr.finish()

    ru = top.table("rules")
    rules = Rules(
        submit_mode=ru.enum("submit_mode", SUBMIT_MODES),
        flag_sharing=ru.enum("flag_sharing", ALLOWED_FORBIDDEN),
        ai_on_platform=ru.enum("ai_on_platform", ALLOWED_FORBIDDEN),
        wrong_answer_stop=ru.get("wrong_answer_stop", int, 3),
        guess_budget=ru.get("guess_budget", int, 0),
        hints_allowed=ru.get("hints_allowed", bool, False),
        live_service_scope=ru.strlist("live_service_scope", []),
        web_state_changing=ru.get("web_state_changing", bool, False),
        public_fetch_allow=ru.strlist("public_fetch_allow", []),
        wrong_penalty=ru.get("wrong_penalty", int, None),
        approved_extras=ru.get("approved_extras", bool, True),
        hint_suggestions=ru.get("hint_suggestions", bool, False),
        pointed_services=ru.enum("pointed_services", ALLOWED_FORBIDDEN, "forbidden"),
        chain_rpc=ru.enum("chain_rpc", ALLOWED_FORBIDDEN, "forbidden"),
        sandboxed_execution=ru.enum("sandboxed_execution", ALLOWED_FORBIDDEN, "forbidden"),
    )
    ru.finish()
    if rules.wrong_penalty is not None and rules.wrong_penalty < 0:
        raise EventError(f"{src}: rules.wrong_penalty must be >= 0 (points lost per wrong answer)")
    if rules.wrong_answer_stop < 1:
        raise EventError(f"{src}: rules.wrong_answer_stop must be >= 1")
    if rules.guess_budget < 0:
        raise EventError(f"{src}: rules.guess_budget must be >= 0")
    if kind == "manual" and rules.submit_mode != "manual":
        raise EventError(f"{src}: platform kind 'manual' requires rules.submit_mode = 'manual'")
    if rules.ai_on_platform == "forbidden" and rules.submit_mode != "manual":
        raise EventError(f"{src}: rules.ai_on_platform = 'forbidden' requires rules.submit_mode = 'manual'")
    if rules.submit_mode == "auto" and not flag.known:
        raise EventError(f"{src}: rules.submit_mode = 'auto' needs known flag.prefixes (an unknown format "
                         "makes auto-submit unsafe; use 'confirm' until the format is confirmed)")

    w = top.table("writeups", required=False)
    writeups = Writeups()
    if w is not None:
        writeups = Writeups(redact_flags=w.get("redact_flags", bool, True),
                            public_repo=w.get("public_repo", str, "") or None,
                            publish_hold=w.get("publish_hold", bool, True))
        w.finish()
    if rules.flag_sharing == "forbidden" and not writeups.redact_flags:
        raise EventError(f"{src}: writeups.redact_flags = false contradicts rules.flag_sharing = 'forbidden' "
                         "(an event that forbids sharing flags must redact them in writeups)")

    b = top.table("budget", required=False)
    budget = Budget()
    if b is not None:
        over_min = b.number("overthink_min_solves", None)
        if over_min is not None and over_min != int(over_min):
            raise EventError(f"{src}: budget.overthink_min_solves must be a whole number, got {over_min}")
        budget = Budget(per_point=b.number("per_point", 0.5), floor=b.number("floor", 25.0),
                        ceiling=b.number("ceiling", 250.0),
                        per_challenge_day=b.number("per_challenge_day", None),
                        overthink_usd=b.number("overthink_usd", None),
                        overthink_max_points=b.number("overthink_max_points", None),
                        overthink_min_solves=int(over_min) if over_min is not None else None)
        b.finish()
    if min(budget.per_point, budget.floor, budget.ceiling) < 0 or (budget.per_challenge_day or 0) < 0:
        raise EventError(f"{src}: budget values must be >= 0")
    if budget.floor > budget.ceiling:
        raise EventError(f"{src}: budget.floor ({budget.floor}) is above budget.ceiling ({budget.ceiling})")
    _over = (budget.overthink_usd, budget.overthink_max_points, budget.overthink_min_solves)
    if any(v is not None for v in _over) and any(v is None for v in _over):
        raise EventError(f"{src}: budget.overthink_usd, overthink_max_points and overthink_min_solves "
                         "must all be set together, or all left unset (the overthink cap needs all three)")
    if budget.overthink_usd is not None and (budget.overthink_usd < 0 or budget.overthink_max_points < 0
                                             or budget.overthink_min_solves < 1):
        raise EventError(f"{src}: budget.overthink_usd and overthink_max_points must be >= 0 and "
                         "overthink_min_solves >= 1")

    hu = top.table("human", required=False)
    human = Human()
    if hu is not None:
        human = Human(confirm_system=hu.get("confirm_system", str, "").strip() or None,
                      checklist=hu.strlist("checklist", []))
        hu.finish()

    dc = top.table("discord", required=False)
    discord = Discord()
    if dc is not None:
        discord = Discord(capture=dc.enum("capture", DISCORD_CAPTURE, Discord.capture),
                          api_base=dc.get("api_base", str, Discord.api_base).strip().rstrip("/"),
                          token_env=dc.get("token_env", str, Discord.token_env).strip(),
                          guild_id=dc.get("guild_id", str, "").strip() or None)
        dc.finish()
        from urllib.parse import urlsplit
        try:
            _parts = urlsplit(discord.api_base)
            _ok = _parts.scheme in ("http", "https") and bool(_parts.hostname) and not _parts.username \
                and not _parts.query and not _parts.fragment and _parts.port != 0
        except ValueError:
            _ok = False
        if not _ok:
            raise EventError(f"{src}: discord.api_base must be an http(s) URL with a host and no "
                             f"credentials, query or fragment; got {discord.api_base!r}")
        if not _ENV_NAME_RE.match(discord.token_env):
            raise EventError(f"{src}: discord.token_env must be the NAME of a CTF_* environment variable "
                             f"(e.g. {DISCORD_TOKEN_ENV}), never the token itself")
        if discord.token_env in ("CTF_TOKEN", "CTF_COOKIE"):
            raise EventError(f"{src}: discord.token_env {discord.token_env!r} is the platform credential; "
                             "a Discord client must never be handed it")
        if discord.guild_id is not None and not _SNOWFLAKE_RE.match(discord.guild_id):
            raise EventError(f"{src}: discord.guild_id must be the server's numeric id as a string")

    sq = top.table("submit", required=False)
    submit = SubmitPace()
    if sq is not None:
        d = SubmitPace()
        submit = SubmitPace(per_minute=sq.get("per_minute", int, d.per_minute),
                            interval_s=sq.number("interval_s", d.interval_s),
                            per_challenge_interval_s=sq.number("per_challenge_interval_s",
                                                               d.per_challenge_interval_s),
                            max_hold_s=sq.number("max_hold_s", d.max_hold_s),
                            rotating_miss_budget=sq.get("rotating_miss_budget", int,
                                                        d.rotating_miss_budget))
        sq.finish()
    if submit.per_minute < 1:
        raise EventError(f"{src}: submit.per_minute must be >= 1")
    if min(submit.interval_s, submit.per_challenge_interval_s, submit.max_hold_s) < 0:
        raise EventError(f"{src}: submit intervals and max_hold_s must be >= 0")
    if submit.rotating_miss_budget < 0:
        raise EventError(f"{src}: submit.rotating_miss_budget must be >= 0")

    sw = top.table("sweep", required=False)
    sweep = SweepPolicy()
    if sw is not None:
        d = SweepPolicy()
        sweep = SweepPolicy(mode=sw.enum("mode", SWEEP_MODES, d.mode),
                            max_count=sw.get("max_count", int, d.max_count),
                            interval_s=sw.number("interval_s", d.interval_s),
                            ttl_s=sw.number("ttl_s", d.ttl_s))
        sw.finish()
    if sweep.max_count < 1:
        raise EventError(f"{src}: sweep.max_count must be >= 1")
    if sweep.interval_s < 0:
        raise EventError(f"{src}: sweep.interval_s must be >= 0")
    if sweep.ttl_s <= 0:
        raise EventError(f"{src}: sweep.ttl_s must be > 0")
    if sweep.authorized and rules.submit_mode == "manual":
        raise EventError(f"{src}: sweep.mode = 'player-authorized' needs rules.submit_mode other than "
                         "'manual' (nothing is sent on a manual event)")

    mo = top.table("models", required=False)
    models = Models()
    if mo is not None:
        models = Models(primary=mo.get("primary", str, Models.primary),
                        fallback=mo.strlist("fallback", list(Models.fallback)),
                        cyber_verified=mo.enum("cyber_verified", CYBER_VERIFIED, Models.cyber_verified),
                        docs=mo.get("docs", str, Models.docs),
                        docs_on_primary=mo.strlist("docs_on_primary", list(Models.docs_on_primary)),
                        effort=mo.enum("effort", EFFORT_LEVELS, Models.effort))
        mo.finish()
        for m in (models.primary, *models.fallback, models.docs):
            if not _MODEL_RE.match(m):
                raise EventError(f"{src}: models: {m!r} is not a model id (must match {_MODEL_RE.pattern})")
        if models.primary in models.fallback:
            raise EventError(f"{src}: models.primary {models.primary!r} is also listed in models.fallback")

    al = top.table("allowance", required=False)
    allowance = Allowance()
    if al is not None:
        allowance = _allowance(al, src)

    ins = top.table("instances", required=False)
    instances = None
    if ins is not None:
        cap = ins.get("cap", int, None)
        if cap is not None and cap < 1:
            raise ins._fail("cap", "must be a positive integer, or omit it for no local cap")
        if "endpoints" not in ins.t:
            raise ins._fail("endpoints", 'table is required (the plugin wiring; e.g. '
                            '{ plugin = "docker_per_team" })')
        endpoints = ins.t.pop("endpoints")
        if not isinstance(endpoints, dict):
            raise ins._fail("endpoints", "must be a table")
        ins.finish()
        from . import instances as _instances
        try:
            _instances.endpoints_from_config(endpoints)   # validate the wiring loudly at load time
        except _instances.InstanceError as e:
            raise EventError(f"{src}: instances.endpoints: {e}") from None
        instances = InstancesCfg(cap=cap, endpoints=endpoints)

    wire = _wire(top.table("wire", required=False), src)
    routing = _routing(top.table("routing", required=False), src, budget)

    top.finish()
    return EventProfile(slug=slug, name=name, start=start, end=end, platform=platform, flag=flag,
                        proof=proof, rules=rules, writeups=writeups, budget=budget, human=human,
                        discord=discord, submit=submit, sweep=sweep, models=models, allowance=allowance,
                        instances=instances, wire=wire, routing=routing,
                        categories=categories, sectors=sectors)


def _routing(r: "_Reader | None", src: str, budget: Budget) -> Routing | None:
    """The optional [routing] table (B-201): structure only. Pricing (every model priced, a rule's
    harness and tier valid for its model) is checked by ctf.router.Router, which reads
    tools/ledger/pricing.json."""
    if r is None:
        return None
    from .stages import SPEND_CATEGORIES
    default_difficulty = r.enum("default_difficulty", ROUTE_DIFFICULTIES, "medium")
    candidate = r.get("verify_candidate", str, "").strip() or None
    top_categories = tuple(c.strip().lower() for c in r.strlist("top_categories", []))
    raw = r.get("route", list, [])
    r.finish()
    if candidate is not None and not _MODEL_RE.match(candidate):
        raise EventError(f"{src}: routing.verify_candidate {candidate!r} is not a model id")
    rules: list[RouteRule] = []
    seen: dict[tuple, int] = {}
    for i, item in enumerate(raw):
        rr = _Reader(src, f"routing.route[{i}]", item)
        role = rr.enum("role", (*SPEND_CATEGORIES, ROUTE_ANY), ROUTE_ANY)
        difficulty = rr.enum("difficulty", (*ROUTE_DIFFICULTIES, ROUTE_ANY), ROUTE_ANY)
        harness = rr.enum("harness", (*ROUTE_HARNESSES, ROUTE_ANY), ROUTE_ANY)
        model = rr.get("model", str, None)
        effort = rr.get("effort", str, None)
        tier = rr.get("tier", str, DEFAULT_TIER)
        budget_usd = rr.number("budget_usd", None)
        rr.finish()
        where = f"{src}: routing.route[{i}]"
        if model is None and effort is None:
            raise EventError(f"{where} routes nothing: give a model, an effort or both")
        if model is not None and not _MODEL_RE.match(model):
            raise EventError(f"{where}.model {model!r} is not a model id (must match {_MODEL_RE.pattern})")
        if effort is not None and effort not in EFFORT_LEVELS:
            raise EventError(f"{where}.effort must be one of {', '.join(EFFORT_LEVELS)}; got {effort!r}")
        if not _TIER_RE.match(tier):
            raise EventError(f"{where}.tier {tier!r} is not a tier name")
        if tier != DEFAULT_TIER and model is None:
            raise EventError(f"{where}.tier {tier!r} needs a model (a speed tier is priced per model)")
        if tier != DEFAULT_TIER and budget_usd is None:
            raise EventError(f"{where}.tier {tier!r} needs an explicit budget_usd (B-033): a speed tier "
                             "costs a multiple of the standard rate and stays off without one")
        if budget_usd is not None:
            if tier == DEFAULT_TIER:
                raise EventError(f"{where}.budget_usd applies only to a speed tier (tier is "
                                 f"{DEFAULT_TIER!r}); the standard tier is capped by [budget]")
            if not budget_usd > 0:
                raise EventError(f"{where}.budget_usd must be > 0")
            if budget_usd > budget.ceiling:
                raise EventError(f"{where}.budget_usd ({budget_usd:g}) is above budget.ceiling "
                                 f"({budget.ceiling:g}): no challenge may spend that much (B-033)")
        key = (role, difficulty, harness)
        if key in seen:
            raise EventError(f"{where} repeats role/difficulty/harness {'/'.join(key)} of "
                             f"routing.route[{seen[key]}]")
        seen[key] = i
        rules.append(RouteRule(role=role, difficulty=difficulty, harness=harness, model=model,
                               effort=effort, tier=tier, budget_usd=budget_usd, index=i))
    return Routing(rules=tuple(rules), default_difficulty=default_difficulty,
                   verify_candidate=candidate, top_categories=top_categories)


_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")


def _allowance(r: _Reader, src: str) -> Allowance:
    d = Allowance()
    tz = r.get("tz", str, d.tz)
    try:
        zone = zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise r._fail("tz", f"is not an IANA time zone: {tz!r}") from None
    raw = r.get("releases", list, [])
    releases = []
    for v in raw:
        if isinstance(v, str):
            try:
                v = _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                raise r._fail("releases", f"holds {v!r}, not an ISO datetime") from None
        if not isinstance(v, _dt.datetime):
            raise r._fail("releases", f"must be a list of datetimes, got {v!r}")
        releases.append(v if v.tzinfo else v.replace(tzinfo=zone))
    a = Allowance(margin_pct=r.number("margin_pct", d.margin_pct), reserve_pct=r.number("reserve_pct", d.reserve_pct),
                  build_ceiling_pct=r.number("build_ceiling_pct", d.build_ceiling_pct),
                  recheck_minutes=r.number("recheck_minutes", d.recheck_minutes),
                  releases=tuple(sorted(releases)), daily_release=r.get("daily_release", str, d.daily_release),
                  tz=tz, daily_usd=r.number("daily_usd", d.daily_usd))
    r.finish()
    for k in ("margin_pct", "reserve_pct", "build_ceiling_pct"):
        if not 0 <= getattr(a, k) <= 100:
            raise EventError(f"{src}: allowance.{k} must be between 0 and 100")
    if a.margin_pct + a.reserve_pct >= 100:
        raise EventError(f"{src}: allowance.margin_pct + allowance.reserve_pct must stay below 100 "
                         "(nothing would be left for solve work)")
    if a.recheck_minutes <= 0:
        raise EventError(f"{src}: allowance.recheck_minutes must be > 0")
    if a.daily_usd < 0:
        raise EventError(f"{src}: allowance.daily_usd must be >= 0")
    if a.daily_release and not _HHMM_RE.match(a.daily_release):
        raise EventError(f"{src}: allowance.daily_release must be \"HH:MM\" (24-hour) or \"\", "
                         f"got {a.daily_release!r}")
    return a


LANE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")   # a lane name (CTF_WIRE_LANE, wire.release_lanes)
WIRE_INT_KEYS = ("per_minute", "release_budget", "reserve", "release_lane_budget")
WIRE_NUM_KEYS = ("release_window_s", "release_poll_free_s", "release_poll_gap_s", "pause_s", "pause_max_s",
              "max_wait_s")


def _wire(w: "_Reader | None", src: str) -> WirePace:
    """The optional [wire] table (B-140)."""
    d = WirePace()
    if w is None:
        return d
    ints = {k: w.get(k, int, getattr(d, k)) for k in WIRE_INT_KEYS}
    nums = {k: w.number(k, getattr(d, k)) for k in WIRE_NUM_KEYS}
    lanes_raw = w.get("release_lanes", dict, {})
    w.finish()
    for k, v in (*ints.items(), *nums.items()):
        if v < 0:
            raise EventError(f"{src}: wire.{k} must be >= 0")
    lanes = []
    for name, n in sorted(lanes_raw.items()):
        if not LANE_RE.fullmatch(name):
            raise EventError(f"{src}: wire.release_lanes key {name!r} must match {LANE_RE.pattern}")
        if isinstance(n, bool) or not isinstance(n, int) or n < 0:
            raise EventError(f"{src}: wire.release_lanes.{name} must be an integer >= 0")
        lanes.append((name, n))
    pace = WirePace(**ints, **nums, release_lanes=tuple(lanes))
    if pace.release_window_s <= 0:
        raise EventError(f"{src}: wire.release_window_s must be > 0")
    for cap in ("per_minute", "release_budget"):
        n = getattr(pace, cap)
        if n and pace.reserve >= n:
            raise EventError(f"{src}: wire.reserve ({pace.reserve}) must be below wire.{cap} ({n}), "
                             "or no read could ever be sent")
    if pace.release_poll_free_s > pace.release_window_s:
        raise EventError(f"{src}: wire.release_poll_free_s ({pace.release_poll_free_s}) is longer than "
                         f"wire.release_window_s ({pace.release_window_s})")
    if pace.pause_s > pace.pause_max_s:
        raise EventError(f"{src}: wire.pause_s ({pace.pause_s}) is above wire.pause_max_s ({pace.pause_max_s})")
    return pace


def load_path(path: str | Path, *, expect_slug: str | None = None) -> EventProfile:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise EventError(f"no event profile at {path}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise EventError(f"{path}: not valid TOML: {e}") from None
    prof = parse(data, src=str(path), expect_slug=expect_slug)
    object.__setattr__(prof, "path", path)
    return prof


def available(root: Path | None = None) -> list[str]:
    root = paths.events_root() if root is None else Path(root)
    if not root.is_dir():
        return []
    return sorted(d.name for d in root.iterdir() if (d / PROFILE_NAME).is_file())


def load(slug: str, root: Path | None = None) -> EventProfile:
    base = paths.event_dir(slug) if root is None else Path(root) / slug
    f = base / PROFILE_NAME
    if not f.is_file():
        have = available(root)
        raise EventError(f"no event profile {slug!r} ({f} missing); available: {', '.join(have) or 'none'}")
    return load_path(f, expect_slug=slug)


def current(root: Path | None = None) -> EventProfile:
    """The active event: $CTF_EVENT, else the only profile under events/. Ambiguity is an error."""
    slug = env.get("CTF_EVENT")
    if slug:
        return load(slug, root)
    have = available(root)
    if len(have) == 1:
        return load(have[0], root)
    if not have:
        raise EventError("no event profile found under events/ and CTF_EVENT is not set")
    raise EventError(f"CTF_EVENT is not set and {len(have)} profiles exist ({', '.join(have)}); "
                     "set CTF_EVENT=<slug>")
