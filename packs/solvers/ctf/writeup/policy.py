"""The writeup policy of one event, derived from its profile (never from a staging file).

    pol = policy.for_profile(event.load("pink"))
    pol.redact            # True when redact_flags is set OR the event forbids sharing flags
    pol.publish_gates(now=..., files=n, blocking=k)   # [Gate(name, ok, reason)], all must pass

The publish gates, in order:
  hold         [writeups] publish_hold is false (the player's go; default true)
  ended        the event is over (dates.end; a bare date ends at the next midnight UTC)
  repo         [writeups] public_repo is set
  content      the public tree has at least one writeup file
  clean        the leak scan found no blocking finding
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
from dataclasses import dataclass
from urllib.parse import urlsplit

from .. import event as _event


class PolicyError(ValueError):
    """The profile cannot answer a question the pipeline must ask (named in the message)."""


@dataclass(frozen=True)
class Gate:
    name: str
    ok: bool
    reason: str

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "reason": self.reason}


def event_end_utc(profile: _event.EventProfile) -> _dt.datetime:
    """When the event ended, as an aware UTC datetime. A bare date means the whole day: the event
    ends at the following midnight UTC (the late side, so a publish is never early)."""
    end = profile.end
    if isinstance(end, _dt.datetime):
        if end.tzinfo is None:
            raise PolicyError(f"{profile.slug}: dates.end {end.isoformat()} has no UTC offset; the publish "
                              "gate cannot tell when the event ended (write e.g. 2026-11-09T12:00:00Z)")
        return end.astimezone(_dt.timezone.utc)
    return _dt.datetime.combine(end + _dt.timedelta(days=1), _dt.time(0), tzinfo=_dt.timezone.utc)


@dataclass(frozen=True)
class Policy:
    slug: str
    name: str
    redact: bool
    sharing_forbidden: bool
    publish_hold: bool
    public_repo: str | None
    end_utc: _dt.datetime
    infra_hosts: tuple[str, ...]        # host globs of the platform and the live services

    def is_infra_host(self, host: str) -> bool:
        h = (host or "").lower().rstrip(".")
        return any(fnmatch.fnmatchcase(h, g) for g in self.infra_hosts)

    def publish_gates(self, *, now: _dt.datetime, files: int, blocking: int) -> list[Gate]:
        if now.tzinfo is None:
            raise PolicyError("publish_gates needs an aware `now`")
        gates = [
            Gate("hold", not self.publish_hold,
                 "publish_hold is false in the profile" if not self.publish_hold else
                 f"publishing is on hold for {self.slug}: set [writeups] publish_hold = false in "
                 f"events/{self.slug}/event.toml only on the player's go"),
            Gate("ended", now >= self.end_utc,
                 f"event ended {self.end_utc.isoformat()}" if now >= self.end_utc else
                 f"event has not ended (ends {self.end_utc.isoformat()}); writeups wait for the end"),
            Gate("repo", bool(self.public_repo),
                 f"public repo {self.public_repo}" if self.public_repo else
                 "no public repo: set [writeups] public_repo in the profile"),
            Gate("content", files > 0,
                 f"{files} file(s) in the public tree" if files else "the public tree has no writeup files"),
            Gate("clean", blocking == 0,
                 "no blocking leak finding" if blocking == 0 else
                 f"{blocking} blocking leak finding(s): fix the staging files and rebuild"),
        ]
        return gates


def _host_globs(profile: _event.EventProfile) -> tuple[str, ...]:
    globs: list[str] = []
    if profile.platform.base_url:
        host = (urlsplit(profile.platform.base_url).hostname or "").lower()
        if host:
            globs.append(host)
    for g in profile.rules.live_service_scope:
        g = g.strip().lower()
        if g:
            globs.append(g)
            if g.startswith("*."):
                globs.append(g[2:])          # the apex of a wildcard scope is event infrastructure too
    return tuple(dict.fromkeys(globs))


def for_profile(profile: _event.EventProfile) -> Policy:
    w = profile.writeups
    forbidden = profile.rules.flag_sharing == "forbidden"
    return Policy(
        slug=profile.slug,
        name=profile.name,
        redact=bool(w.redact_flags or forbidden),
        sharing_forbidden=forbidden,
        publish_hold=bool(w.publish_hold),
        public_repo=w.public_repo,
        end_utc=event_end_utc(profile),
        infra_hosts=_host_globs(profile),
    )
