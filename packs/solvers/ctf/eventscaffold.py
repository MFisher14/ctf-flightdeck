"""New-event scaffold: build and write events/<slug>/event.toml, fetching CTFd categories when it can.

    from ctf import eventscaffold as sc
    data = sc.profile_data("acme", name="ACME CTF", start=..., end=..., kind="ctfd", base_url=...)
    prof = sc.validate(data, "acme")                       # ctf.event.parse, the one validator
    cats = sc.fetch_categories(prof)                        # platform adapter's list_challenges()
    sc.write_profile(data, events_root / "acme" / "event.toml", header=[...])

Rules and target sectors are hand-entered (CLI options or by editing the written file): organizer
rule pages are free-form and nothing here scrapes them. Categories come from the platform adapter's
list_challenges() when a base URL and a token are configured and the profile allows automation on
the platform; a failed fetch is an error, never a silent empty list.

The TOML writer covers exactly the value types an event profile uses (str, bool, int, float, date,
datetime, list of str, inline table) and every write is re-read and compared with what was meant to
be written, so a writer bug cannot produce a profile that loads differently.
"""
from __future__ import annotations

import datetime as _dt
import json
import tomllib
from pathlib import Path
from typing import Any, Callable

from . import env
from . import event as _event


class ScaffoldError(ValueError):
    """The scaffold cannot do what was asked; the message names the reason."""


# ------------------------------------------------------------------------------------------ dates

def parse_when(value: str, what: str) -> _dt.date | _dt.datetime:
    """ISO date (2026-12-01) or datetime (2026-12-01T13:00:00Z / +00:00)."""
    v = value.strip()
    try:
        if "T" in v or " " in v:
            return _dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        return _dt.date.fromisoformat(v)
    except ValueError:
        raise ScaffoldError(f"{what} is not an ISO date or datetime: {value!r}") from None


# ------------------------------------------------------------------------------------------ profile

def profile_data(slug: str, *, name: str, start: _dt.date | _dt.datetime, end: _dt.date | _dt.datetime,
                 kind: str, base_url: str | None = None, team: str | None = None,
                 categories: list[str] | tuple[str, ...] = (), sectors: list[str] | tuple[str, ...] = (),
                 prefixes: list[str] | tuple[str, ...] = (), body: str | None = None, case: str = "exact",
                 proof_pattern: str | None = None, submit_mode: str, wrong_answer_stop: int = 3,
                 guess_budget: int = 0, hints_allowed: bool = False, flag_sharing: str = "forbidden",
                 ai_on_platform: str, live_service_scope: list[str] | tuple[str, ...] = (),
                 web_state_changing: bool = False, public_fetch_allow: list[str] | tuple[str, ...] = (),
                 redact_flags: bool = True,
                 public_repo: str | None = None, wrong_penalty: int | None = None,
                 approved_extras: bool = True, hint_suggestions: bool = False,
                 pointed_services: str = "forbidden", sweep_mode: str = "forbidden", chain_rpc: str = "forbidden",
                 instances: dict[str, Any] | None = None,
                 sandboxed_execution: str = "forbidden") -> dict[str, Any]:
    """The decoded-TOML mapping for a new profile, every section written out (defaults included) so
    the file shows the player each rule they may want to change."""
    platform: dict[str, Any] = {"kind": kind}
    if base_url:
        platform["base_url"] = base_url
    if team:
        platform["team"] = team
    flag: dict[str, Any] = {"prefixes": list(prefixes)}
    if body is not None:
        flag["body"] = body
    flag["case"] = case
    data: dict[str, Any] = {
        "slug": slug,
        "name": name,
        "categories": list(categories),
        "sectors": list(sectors),
        "dates": {"start": start, "end": end},
        "platform": platform,
        "flag": flag,
    }
    if proof_pattern:
        data["proof"] = {"pattern": proof_pattern, "case": "exact"}
    data["rules"] = {
        "submit_mode": submit_mode,
        "wrong_answer_stop": wrong_answer_stop,
        "guess_budget": guess_budget,
        "hints_allowed": hints_allowed,
        "flag_sharing": flag_sharing,
        "ai_on_platform": ai_on_platform,
        "live_service_scope": list(live_service_scope),
        "web_state_changing": web_state_changing,
        "public_fetch_allow": list(public_fetch_allow),
        "approved_extras": approved_extras,              # B-173 policy fields
        "hint_suggestions": hint_suggestions,
        "pointed_services": pointed_services,
        "chain_rpc": chain_rpc,                          # B-243: read-only EVM JSON-RPC; off by default
        "sandboxed_execution": sandboxed_execution,      # B-242: runtime adapters, off unless allowed
    }
    if wrong_penalty is not None:                        # absent = the penalty is not known
        data["rules"]["wrong_penalty"] = wrong_penalty
    data["writeups"] = {"redact_flags": redact_flags, "publish_hold": True}   # the player's go clears the hold
    if public_repo:
        data["writeups"]["public_repo"] = public_repo
    b = _event.Budget()
    data["budget"] = {"per_point": b.per_point, "floor": b.floor, "ceiling": b.ceiling}
    q = _event.SubmitPace()          # the team's submit queue (B-006); tune per event
    data["submit"] = {"per_minute": q.per_minute, "interval_s": q.interval_s,
                      "per_challenge_interval_s": q.per_challenge_interval_s, "max_hold_s": q.max_hold_s,
                      "rotating_miss_budget": q.rotating_miss_budget}
    s = _event.SweepPolicy()         # player-authorized sweeps (B-173); the guard stays on by default
    data["sweep"] = {"mode": sweep_mode, "max_count": s.max_count, "interval_s": s.interval_s,
                     "ttl_s": s.ttl_s}
    m = _event.Models()   # B-100: written out so the player records the cyber verified status (O-3)
    data["models"] = {"primary": m.primary, "fallback": list(m.fallback),
                      "cyber_verified": m.cyber_verified, "effort": m.effort}   # B-095: launch-pinned effort
    a = _event.Allowance()   # B-171: harness quota reserve; the player fills in releases / daily_release
    data["allowance"] = {"margin_pct": a.margin_pct, "reserve_pct": a.reserve_pct,
                         "build_ceiling_pct": a.build_ceiling_pct, "recheck_minutes": a.recheck_minutes,
                         "releases": list(a.releases), "daily_release": a.daily_release, "tz": a.tz,
                         "daily_usd": a.daily_usd}
    # B-003: an event with a per-team container plugin carries [instances]. It is omitted by default
    # (not every event has containers, and the plugin is probed per event), but a scaffold may supply it.
    if instances is not None:
        data["instances"] = dict(instances)
    dc = _event.Discord()    # B-112: Discord recon stays player-paste only until the player clears a bot
    data["discord"] = {"capture": dc.capture, "api_base": dc.api_base, "token_env": dc.token_env,
                       "guild_id": ""}
    wp = _event.WirePace()   # B-140: journal every request; 0 caps until the platform's limit is measured
    data["wire"] = {k: getattr(wp, k) for k in (*_event.WIRE_INT_KEYS, *_event.WIRE_NUM_KEYS)}
    data["wire"]["release_lanes"] = {}
    return data


def validate(data: dict[str, Any], slug: str) -> _event.EventProfile:
    return _event.parse(data, src=f"events/{slug}/{_event.PROFILE_NAME} (new)", expect_slug=slug)


def merge_categories(*groups: list[str] | tuple[str, ...]) -> list[str]:
    """Union in first-seen order; spellings that differ only in case count once (first one wins)."""
    seen: set[str] = set()
    out: list[str] = []
    for g in groups:
        for c in g:
            c = c.strip()
            if c and c.casefold() not in seen:
                seen.add(c.casefold())
                out.append(c)
    return out


# ------------------------------------------------------------------------------------------ platform

def token_configured() -> bool:
    """True when a platform token is set (CTF_TOKEN or a legacy spelling). Never returns the value."""
    return env.get("CTF_TOKEN") is not None


def fetch_refusal(profile: _event.EventProfile) -> str | None:
    """Why the profile forbids reading the platform from here, or None when it allows it."""
    if profile.platform.kind == "manual":
        return "the platform kind is manual (no platform automation)"
    if profile.rules.ai_on_platform == "forbidden":
        return "rules.ai_on_platform is forbidden (no automation may touch the platform)"
    if not profile.platform.base_url:
        return "no platform base URL"
    return None


def fetch_categories(profile: _event.EventProfile,
                     get_adapter: Callable[[_event.EventProfile], Any] | None = None) -> tuple[list[str], int]:
    """(categories in platform order, number of challenges listed) from the adapter's
    list_challenges(). Raises ScaffoldError when the profile forbids it or the call fails."""
    why = fetch_refusal(profile)
    if why:
        raise ScaffoldError(f"refusing to read the platform: {why}")
    if get_adapter is None:
        from .platform import get_adapter  # local: the platform package imports event
    from .platform import PlatformError
    try:
        challenges = get_adapter(profile).list_challenges()
    except PlatformError as e:
        raise ScaffoldError(f"could not list challenges from {profile.platform.base_url}: {e}") from None
    cats = merge_categories([c.category for c in challenges if c.category])
    return cats, len(challenges)


# ------------------------------------------------------------------------------------------ TOML

def _toml_str(s: str) -> str:
    # JSON string escapes are a subset of TOML basic-string escapes; DEL must be escaped in TOML.
    return json.dumps(s, ensure_ascii=True).replace("\x7f", "\\u007f")


def _toml_value(v: Any, key: str) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        r = repr(v)
        return r if any(ch in r for ch in ".en") else r + ".0"
    if isinstance(v, str):
        return _toml_str(v)
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x, key) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{k} = {_toml_value(x, f'{key}.{k}')}" for k, x in v.items()) + " }"
    raise ScaffoldError(f"cannot write {key} of type {type(v).__name__} to TOML")


_INLINE_TABLES = ("dates",)


def to_toml(data: dict[str, Any], header: list[str] | tuple[str, ...] = ()) -> str:
    lines = [f"# {h}".rstrip() for h in header]
    tables = []
    for k, v in data.items():
        if isinstance(v, dict) and k not in _INLINE_TABLES:
            tables.append((k, v))
        else:
            lines.append(f"{k} = {_toml_value(v, k)}")
    for k, t in tables:
        lines.append("")
        lines.append(f"[{k}]")
        for kk, vv in t.items():
            lines.append(f"{kk} = {_toml_value(vv, f'{k}.{kk}')}")
    text = "\n".join(lines) + "\n"
    if tomllib.loads(text) != data:
        raise ScaffoldError("internal: the TOML writer did not round-trip the profile; nothing written")
    return text


def write_profile(data: dict[str, Any], path: Path, header: list[str] | tuple[str, ...] = ()) -> _event.EventProfile:
    """Validate, write and re-load events/<slug>/event.toml; returns the loaded profile."""
    path = Path(path)
    slug = path.parent.name
    want = validate(data, slug)
    text = to_toml(data, header)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    got = _event.load_path(path, expect_slug=slug)
    object.__setattr__(want, "path", got.path)
    if got != want:
        raise ScaffoldError(f"{path}: the written profile loads differently from what was meant")
    return got
