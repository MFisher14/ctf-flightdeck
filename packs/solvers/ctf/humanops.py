"""Human-only work, surfaced early (B-169): task cards, the OSINT final-pin queue, the off-platform
confirm list with its reconciliation report, and the evening checklist.

Some steps only the player can take: repair the network, plug in the power, set /model and /effort,
wait out or reset a usage limit, click a /permissions prompt, read a Discord channel, run a paid
index lookup (Censys, FOFA), drop the final map pin, confirm points in an off-platform system
(Huntress: CourseStack). In 2026 these surfaced as stalls. Here they are written down as they appear
and batched for the player.

    from ctf import humanops
    ops = humanops.HumanOps(profile)                 # memory: the event ledger (ctf.ledger)
    card = ops.add_card("discord", ask="...", need="...", challenge_id="9091")
    pin = ops.add_pin("77", ask="...", decimals=4, candidates=["14.59,120.98 Intramuros"])
    ops.cards(); ops.pin_queue(); ops.answer(card.id, "value"); ops.drop(card.id, "reason")
    ops.add_confirm("12#a1", flag="flag{...}", points=50)    # needs [human] confirm_system
    ops.confirm_list(); ops.mark_confirmed("12#a1")
    rep = ops.reconcile(humanops.read_truth(path))   # against the Game Master record
    print(humanops.render_checklist(ops.checklist(date)))

Ledger events (all carry event_slug): human.card (a new card), human.card_answer, human.card_drop,
human.confirm (an item for the confirm list), human.confirm_done (the player ticked it),
human.reconcile (the counts of a report). The Game Master side of the confirm list is the gate's own
"platform.submit" records with an accepted status (ctf/platform/rules.py), optionally widened with
the adapter's live team_solves().

Nothing here contacts the off-platform system: whether a scripted CourseStack submission is allowed
is undecided, so the confirm list is for the player's hands only. The reconciliation's source of truth
is a CSV the player exports or types from that system (columns: challenge, optional points, flag).

Flags: with flag_sharing = "forbidden" the ledger keeps only a flag's SHA-256 (as rules.py does), so a
confirm item then needs `where` (the file that holds the value), and a card answer that contains a
flag in the event format is refused.
"""
from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import flagfmt, ledger, paths
from .event import EventProfile

CARD_KINDS = ("discord", "lookup", "pin", "label", "access", "other")
CARD_KIND_HELP = {
    "discord": "read something only a team member can see (a Discord channel, a ticket, an email)",
    "lookup": "a lookup behind an account or paywall (Censys, FOFA, Shodan, a paid index)",
    "pin": "the final map pin: an exact coordinate the agents could narrow but not fix",
    "label": "read an exact label, sign, review count or name off a map, Street View or a photo",
    "access": "an access step: a login, 2FA, VPN, a /permissions click, a platform action",
    "other": "anything else only the player can do",
}
EV_CARD, EV_ANSWER, EV_DROP = "human.card", "human.card_answer", "human.card_drop"
EV_CONFIRM, EV_CONFIRM_DONE, EV_RECONCILE = "human.confirm", "human.confirm_done", "human.reconcile"
SUBMIT_EVENT = "platform.submit"          # written by ctf/platform/rules.py
ACCEPTED = ("correct", "already_solved")
DEFAULT_PIN_DECIMALS = 4

# Standing human-only items, from the 2026 session reports: each was a stall at least once.
STANDING = (
    ("network", "Network: the machine is online and stays online (Wi-Fi or cable, and the VPN if the "
                "event uses one). Agents cannot repair a dropped link."),
    ("power", "Power: on mains, with sleep disabled for the run. Agents cannot plug in a charger."),
    ("model", "Model and effort: each harness is on the intended model and effort (/model and /effort "
              "in Claude, the model in the Codex config). Only you can set them."),
    ("limits", "Usage limits: note each harness's reset time and what is left. A limit is lifted only "
               "by waiting or by you."),
    ("permissions", "Permissions: a fresh session runs the event tools with no /permissions click "
                    "(the allowlist is approved). An unattended prompt stalls the lane."),
    ("credentials", "Credentials: the platform token or cookie is in place and does not expire during "
                    "the event. Agents never handle it."),
)


class HumanOpsError(ValueError):
    """A bad card, answer or confirm request, or missing configuration. The message names it."""


# ------------------------------------------------------------------------------------------ pins

_COORD = r"([+-]?\d{1,3}(?:\.(\d+))?)"
_PIN_RE = re.compile(rf"^\s*{_COORD}\s*,\s*{_COORD}\s*(?:\s(.*))?$")


@dataclass(frozen=True)
class Pin:
    lat: float
    lon: float
    text: str            # the coordinate as written, decimals kept
    decimals: int        # the fewer of the two decimal counts
    note: str = ""

    @property
    def map_url(self) -> str:
        return f"https://www.google.com/maps/search/?api=1&query={self.text}"


def parse_pin(text: str, *, allow_note: bool = False) -> Pin:
    """'lat,lon' (decimal degrees) -> Pin. With allow_note, text after the coordinate is a note."""
    m = _PIN_RE.match(text or "")
    if not m or (m.group(5) and not allow_note):
        raise HumanOpsError(f"{text!r} is not a pin: write decimal degrees as 'lat,lon', e.g. "
                            "'14.5995,120.9842'" + (" (a note may follow after a space)" if allow_note else ""))
    lat, lon = float(m.group(1)), float(m.group(3))
    if not -90.0 <= lat <= 90.0:
        raise HumanOpsError(f"{text!r}: latitude {lat} is outside -90..90")
    if not -180.0 <= lon <= 180.0:
        raise HumanOpsError(f"{text!r}: longitude {lon} is outside -180..180")
    dec = min(len(m.group(2) or ""), len(m.group(4) or ""))
    return Pin(lat, lon, f"{m.group(1)},{m.group(3)}", dec, (m.group(5) or "").strip())


# ------------------------------------------------------------------------------------------ records

@dataclass(frozen=True)
class Card:
    id: str
    kind: str
    ask: str
    need: str
    challenge_id: str | None = None
    why: str = ""
    source: str = ""
    opened: float = 0.0
    status: str = "open"                 # open | answered | dropped
    answer: str | None = None
    by: str = ""
    closed: float | None = None
    reason: str = ""
    decimals: int | None = None          # pin cards: decimals the answer must carry
    candidates: tuple[Pin, ...] = ()     # pin cards: the agents' best candidates

    def age(self, now: float) -> float:
        return (self.closed if self.closed is not None else now) - self.opened


@dataclass(frozen=True)
class ConfirmItem:
    challenge_id: str
    source: str                          # "agent" (an explicit item) | "game master" | "game master (live)"
    since: float
    flag: str | None = None
    flag_sha256: str | None = None
    where: str | None = None
    points: float | None = None
    name: str | None = None
    note: str = ""
    done: bool = False
    done_at: float | None = None
    done_by: str = ""

    @property
    def key(self) -> str:
        return _norm_id(self.challenge_id)


@dataclass(frozen=True)
class TruthRow:
    challenge_id: str
    points: float | None = None
    flag: str | None = None
    line: int = 0


@dataclass(frozen=True)
class Reconciliation:
    system: str
    agree: tuple[ConfirmItem, ...] = ()
    missing: tuple[ConfirmItem, ...] = ()              # on the Game Master record, not in the system
    extra: tuple[TruthRow, ...] = ()                   # in the system, no Game Master record
    flag_mismatch: tuple[tuple[ConfirmItem, TruthRow], ...] = ()
    points_mismatch: tuple[tuple[ConfirmItem, TruthRow], ...] = ()

    @property
    def clean(self) -> bool:
        return not (self.missing or self.extra or self.flag_mismatch or self.points_mismatch)

    def counts(self) -> dict[str, int]:
        return {"agree": len(self.agree), "missing": len(self.missing), "extra": len(self.extra),
                "flag_mismatch": len(self.flag_mismatch), "points_mismatch": len(self.points_mismatch)}


@dataclass(frozen=True)
class ChecklistItem:
    section: str
    text: str
    ref: str = ""


@dataclass(frozen=True)
class Checklist:
    event: str
    for_date: _dt.date
    when: str
    items: tuple[ChecklistItem, ...] = field(default_factory=tuple)

    def section(self, name: str) -> list[ChecklistItem]:
        return [i for i in self.items if i.section == name]


def _norm_id(cid: str) -> str:
    return " ".join(str(cid).split()).lower()


def _key(cid: str) -> str:
    return _norm_id(cid).split("#", 1)[0]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _text(value: str | None, what: str, *, required: bool = True) -> str:
    v = (value or "").strip()
    if required and not v:
        raise HumanOpsError(f"{what} is required and may not be empty")
    return v


# ------------------------------------------------------------------------------------------ the store

class HumanOps:
    def __init__(self, profile: EventProfile, workdir: Path | None = None, *, clock=time.time):
        self.profile = profile
        self._workdir = workdir
        self._clock = clock

    @property
    def workdir(self) -> Path:
        return self._workdir if self._workdir is not None else paths.workdir(self.profile.slug)

    def _records(self) -> list[dict]:
        return [r for r in ledger.read(self.workdir) if r.get("event_slug") == self.profile.slug]

    def _append(self, ev: str, **fields) -> dict:
        return ledger.append(ev, workdir=self.workdir, event_slug=self.profile.slug, **fields)

    # -------------------------------------------------------------------------- cards
    def add_card(self, kind: str, *, ask: str, need: str, challenge_id: str | None = None,
                 why: str = "", source: str = "") -> Card:
        if kind not in CARD_KINDS:
            raise HumanOpsError(f"card kind must be one of {', '.join(CARD_KINDS)}; got {kind!r}")
        if kind == "pin":
            raise HumanOpsError("a pin card goes through add_pin (`ctf human add-pin`): it carries the "
                                "decimals the answer needs and the candidates")
        return self._new_card(kind, ask=_text(ask, "ask"), need=_text(need, "need"),
                              challenge_id=_text(challenge_id, "challenge", required=False) or None,
                              why=_text(why, "why", required=False),
                              source=_text(source, "source", required=False))

    def add_pin(self, challenge_id: str, *, ask: str, decimals: int = DEFAULT_PIN_DECIMALS,
                candidates: Iterable[str] = (), why: str = "", source: str = "") -> Card:
        if isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 8:
            raise HumanOpsError(f"decimals must be an integer 0..8; got {decimals!r}")
        cands = [parse_pin(c, allow_note=True) for c in candidates]
        return self._new_card("pin", ask=_text(ask, "ask"),
                              need=f"one coordinate 'lat,lon' in decimal degrees, at least {decimals} "
                                   "decimals on each",
                              challenge_id=_text(challenge_id, "challenge"),
                              why=_text(why, "why", required=False),
                              source=_text(source, "source", required=False), decimals=decimals,
                              candidates=[{"text": p.text, "note": p.note} for p in cands])

    def _new_card(self, kind: str, **fields) -> Card:
        if self.profile.rules.flag_sharing == "forbidden":
            ff = flagfmt.for_profile(self.profile)
            for name in ("ask", "need", "why", "source"):
                if fields.get(name) and ff.find_flags(fields[name]):
                    raise HumanOpsError(f"event {self.profile.slug} forbids flag sharing, so the ledger keeps "
                                        f"no flag values: the card's {name} contains a flag; refer to the "
                                        "file that holds it instead")
        existing = {c.id for c in self.cards(status=None)}
        cid = "h" + secrets.token_hex(4)
        while cid in existing:
            cid = "h" + secrets.token_hex(4)
        fields = {k: v for k, v in fields.items() if v not in (None, "", [])}
        self._append(EV_CARD, card_id=cid, kind=kind, opened=self._clock(), **fields)
        return self.card(cid)

    def cards(self, status: str | None = "open", kind: str | None = None) -> list[Card]:
        """Cards oldest first. status: "open" (default), "answered", "dropped", or None for all."""
        if status not in (None, "open", "answered", "dropped"):
            raise HumanOpsError(f"status must be open, answered, dropped or None; got {status!r}")
        by_id: dict[str, Card] = {}
        for r in self._records():
            ev = r.get("event")
            if ev == EV_CARD:
                by_id[r["card_id"]] = Card(
                    id=r["card_id"], kind=r["kind"], ask=r["ask"], need=r["need"],
                    challenge_id=r.get("challenge_id"), why=r.get("why", ""), source=r.get("source", ""),
                    opened=float(r.get("opened", r["ts"])), decimals=r.get("decimals"),
                    candidates=tuple(parse_pin(c["text"] + (" " + c["note"] if c.get("note") else ""),
                                               allow_note=True) for c in r.get("candidates", ())))
            elif ev in (EV_ANSWER, EV_DROP) and r.get("card_id") in by_id:
                c = by_id[r["card_id"]]
                if c.status != "open":
                    continue
                kw = dict(c.__dict__)
                kw.update(status="answered" if ev == EV_ANSWER else "dropped", closed=float(r["ts"]),
                          by=r.get("by", ""), answer=r.get("answer"), reason=r.get("reason", ""))
                by_id[c.id] = Card(**kw)
        out = sorted(by_id.values(), key=lambda c: (c.opened, c.id))
        return [c for c in out if (status is None or c.status == status) and (kind is None or c.kind == kind)]

    def card(self, card_id: str) -> Card:
        for c in self.cards(status=None):
            if c.id == card_id:
                return c
        raise HumanOpsError(f"no task card {card_id!r} for event {self.profile.slug}")

    def pin_queue(self) -> list[Card]:
        return self.cards(status="open", kind="pin")

    def answer(self, card_id: str, value: str, *, by: str = "") -> Card:
        c = self.card(card_id)
        if c.status != "open":
            raise HumanOpsError(f"card {card_id} is already {c.status}")
        value = _text(value, "answer")
        if c.kind == "pin":
            p = parse_pin(value)
            if p.decimals < (c.decimals or 0):
                raise HumanOpsError(f"card {card_id} needs at least {c.decimals} decimals on each "
                                    f"coordinate; {value!r} has {p.decimals}")
            value = p.text
        if self.profile.rules.flag_sharing == "forbidden" and flagfmt.for_profile(self.profile).find_flags(value):
            raise HumanOpsError(f"event {self.profile.slug} forbids flag sharing, so the ledger keeps no flag "
                                "values: put the flag in the challenge folder and add it with "
                                "`ctf human confirm --where <file>` or submit it, not as a card answer")
        self._append(EV_ANSWER, card_id=card_id, answer=value, by=_text(by, "by", required=False))
        return self.card(card_id)

    def drop(self, card_id: str, reason: str, *, by: str = "") -> Card:
        c = self.card(card_id)
        if c.status != "open":
            raise HumanOpsError(f"card {card_id} is already {c.status}")
        self._append(EV_DROP, card_id=card_id, reason=_text(reason, "reason"),
                     by=_text(by, "by", required=False))
        return self.card(card_id)

    # -------------------------------------------------------------------------- confirm list
    def confirm_system(self) -> str:
        s = self.profile.human.confirm_system
        if not s:
            raise HumanOpsError(f"event {self.profile.slug} has no off-platform confirm system: set "
                                f"[human] confirm_system in events/{self.profile.slug}/event.toml")
        return s

    def add_confirm(self, challenge_id: str, *, flag: str | None = None, where: str | None = None,
                    points: float | None = None, name: str | None = None, note: str = "") -> ConfirmItem:
        self.confirm_system()
        cid = _text(challenge_id, "challenge")
        flag, where = _text(flag, "flag", required=False), _text(where, "where", required=False)
        if not flag and not where:
            raise HumanOpsError("a confirm item needs the flag (--flag) or the file that holds it (--where)")
        if points is not None and (isinstance(points, bool) or points < 0):
            raise HumanOpsError(f"points must be a number >= 0; got {points!r}")
        fields: dict = {"challenge_id": cid}
        if flag:
            if self.profile.rules.flag_sharing == "forbidden":
                if not where:
                    raise HumanOpsError(f"event {self.profile.slug} forbids flag sharing: the ledger keeps "
                                        "only the flag's SHA-256, so give --where <file holding the value>")
                fields["flag_sha256"] = _sha(flag)
            else:
                fields["flag"] = flag
        for k, v in (("where", where), ("points", points), ("name", _text(name, "name", required=False)),
                     ("note", _text(note, "note", required=False))):
            if v not in (None, ""):
                fields[k] = v
        self._append(EV_CONFIRM, **fields)
        return next(i for i in self.confirm_list(include_done=True) if i.key == _norm_id(cid))

    def confirm_list(self, *, include_done: bool = False, live_solves: Iterable | None = None) -> list[ConfirmItem]:
        """What the player must confirm by hand: every explicit item, plus every answer the Game Master
        accepted through the gate that has no explicit item. `live_solves` (the adapter's
        team_solves(), TeamSolve-like objects with .challenge_id) adds solves the ledger lacks."""
        self.confirm_system()
        items: dict[str, ConfirmItem] = {}
        gm: dict[str, ConfirmItem] = {}
        done: dict[str, dict] = {}
        for r in self._records():
            ev = r.get("event")
            if ev == EV_CONFIRM:
                k = _norm_id(r["challenge_id"])
                items[k] = ConfirmItem(challenge_id=r["challenge_id"], source="agent", since=float(r["ts"]),
                                       flag=r.get("flag"), flag_sha256=r.get("flag_sha256"),
                                       where=r.get("where"), points=r.get("points"), name=r.get("name"),
                                       note=r.get("note", ""))
                done.pop(k, None)            # a re-added (corrected) item is pending again
            elif ev == EV_CONFIRM_DONE:
                done[_norm_id(r["challenge_id"])] = r
            elif ev == SUBMIT_EVENT and r.get("status") in ACCEPTED:
                k = _norm_id(r.get("challenge_id", ""))
                if k and k not in gm:
                    gm[k] = ConfirmItem(challenge_id=r["challenge_id"], source="game master",
                                        since=float(r["ts"]), flag=r.get("flag"),
                                        flag_sha256=r.get("flag_sha256"))
        for k, it in gm.items():
            items.setdefault(k, it)
        for s in live_solves or ():
            cid = str(getattr(s, "challenge_id", "") or "")
            if not cid:
                continue
            k = _norm_id(cid)
            if k not in items and not any(_key(x) == k for x in items):
                items[k] = ConfirmItem(challenge_id=cid, source="game master (live)", since=self._clock())
        out = []
        for k, it in items.items():
            d = done.get(k)
            if d is not None:
                kw = dict(it.__dict__)
                kw.update(done=True, done_at=float(d["ts"]), done_by=d.get("by", ""))
                it = ConfirmItem(**kw)
            if include_done or not it.done:
                out.append(it)
        return sorted(out, key=lambda i: (i.since, i.key))

    def mark_confirmed(self, challenge_id: str, *, by: str = "") -> ConfirmItem:
        k = _norm_id(_text(challenge_id, "challenge"))
        pending = {i.key: i for i in self.confirm_list()}
        if k not in pending:
            known = {i.key for i in self.confirm_list(include_done=True)}
            why = "is already confirmed" if k in known else "is not on the confirm list"
            raise HumanOpsError(f"{challenge_id!r} {why} for {self.confirm_system()}")
        self._append(EV_CONFIRM_DONE, challenge_id=pending[k].challenge_id,
                     by=_text(by, "by", required=False))
        return next(i for i in self.confirm_list(include_done=True) if i.key == k)

    # -------------------------------------------------------------------------- reconciliation
    def reconcile(self, truth: Iterable[TruthRow], *, live_solves: Iterable | None = None,
                  record: bool = True) -> Reconciliation:
        """Compare the Game Master record (the confirm list, confirmed or not) with the player's export
        of the off-platform system, which is the source of truth for points."""
        system = self.confirm_system()
        items = self.confirm_list(include_done=True, live_solves=live_solves)
        truth = list(truth)
        exact = {_norm_id(t.challenge_id): t for t in truth}
        bare = {_norm_id(t.challenge_id): t for t in truth if "#" not in t.challenge_id}
        used: set[int] = set()
        agree, missing, flag_mm, pts_mm = [], [], [], []
        ff = flagfmt.for_profile(self.profile)
        for it in items:
            t = exact.get(it.key) or bare.get(_key(it.challenge_id))
            if t is None:
                missing.append(it)
                continue
            used.add(id(t))
            bad = False
            if t.flag and (it.flag or it.flag_sha256):
                theirs = _canon(ff, t.flag)
                same = (_canon(ff, it.flag) == theirs) if it.flag else (
                    it.flag_sha256 in (_sha(t.flag.strip()), _sha(theirs)))
                if not same:
                    flag_mm.append((it, t))
                    bad = True
            if t.points is not None and it.points is not None and abs(t.points - it.points) > 1e-9:
                pts_mm.append((it, t))
                bad = True
            if not bad:
                agree.append(it)
        extra = [t for t in truth if id(t) not in used]
        rep = Reconciliation(system, tuple(agree), tuple(missing), tuple(extra), tuple(flag_mm), tuple(pts_mm))
        if record:
            self._append(EV_RECONCILE, system=system, **rep.counts())
        return rep

    # -------------------------------------------------------------------------- the checklist
    def checklist(self, for_date: _dt.date | None = None) -> Checklist:
        today = _dt.datetime.fromtimestamp(self._clock()).date()
        day = for_date or today + _dt.timedelta(days=1)
        prof, rules = self.profile, self.profile.rules
        start, end = _as_date(prof.start), _as_date(prof.end)
        if day < start:
            when = f"before the event: it starts {start.isoformat()} ({(start - day).days} day(s) later)"
        elif day > end:
            when = f"after the event: it ended {end.isoformat()}"
        else:
            when = f"day {(day - start).days + 1} of {(end - start).days + 1}"
        items: list[ChecklistItem] = [ChecklistItem("standing", t, ref) for ref, t in STANDING]
        items += [ChecklistItem("event", t, "profile:human.checklist") for t in prof.human.checklist]
        if prof.manual:
            items.append(ChecklistItem("event", "Manual mode: no automation reaches the platform. You pull "
                                       "each challenge into the drop folder and submit every flag yourself.",
                                       "profile:rules.submit_mode"))
        elif rules.submit_mode == "confirm":
            items.append(ChecklistItem("event", "Submissions wait for your yes (submit_mode = confirm): be "
                                       "reachable at every release time.", "profile:rules.submit_mode"))
        if not prof.flag.known:
            items.append(ChecklistItem("event", "Flag format unknown: confirm it from the first accepted flag, "
                                       "then set flag.prefixes in the profile.", "profile:flag.prefixes"))
        if rules.live_service_scope:
            items.append(ChecklistItem("event", "Live targets in scope (" + ", ".join(rules.live_service_scope)
                                       + "): reachable from this machine, VPN up if one is needed.",
                                       "profile:rules.live_service_scope"))
        if prof.human.confirm_system:
            pending = self.confirm_list()
            items.append(ChecklistItem("event", f"Confirm points in {prof.human.confirm_system} by hand: "
                                       f"{len(pending)} item(s) pending (`ctf human confirm-list`), then "
                                       "reconcile against your export (`ctf human reconcile`).",
                                       "profile:human.confirm_system"))
            for it in pending:
                items.append(ChecklistItem("confirm", confirm_line(it), it.challenge_id))
        now = self._clock()
        for c in self.cards():
            sec = "pin" if c.kind == "pin" else "card"
            cands = "; candidates: " + ", ".join(p.text + (f" ({p.note})" if p.note else "")
                                                 for p in c.candidates) if c.candidates else ""
            items.append(ChecklistItem(sec, f"[{c.id}] {_card_head(c)}: {c.ask} -> {c.need}{cands} "
                                            f"(open {_dur(c.age(now))})", c.id))
        return Checklist(prof.slug, day, when, tuple(items))


# ------------------------------------------------------------------------------------------ helpers

def _canon(ff, value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    try:
        return ff.normalize(v)
    except ValueError:
        return v


def _as_date(v) -> _dt.date:
    return v.date() if isinstance(v, _dt.datetime) else v


def _dur(seconds: float) -> str:
    s = max(int(seconds), 0)
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _card_head(c: Card) -> str:
    return c.kind + (f" / challenge {c.challenge_id}" if c.challenge_id else "")


def confirm_line(it: ConfirmItem) -> str:
    who = f"{it.challenge_id}" + (f" ({it.name})" if it.name else "")
    if it.flag:
        val = it.flag
    elif it.where:
        val = f"value in {it.where}"
    elif it.flag_sha256:
        val = f"sha256 {it.flag_sha256[:12]}..., value not in the ledger"
    else:
        val = "value unknown: solved on the platform, find the flag before confirming"
    pts = f", {it.points:g} pts" if it.points is not None else ""
    return f"{who}: {val}{pts} [{it.source}]"


def read_truth(path: str | Path) -> list[TruthRow]:
    """The player's export of the off-platform system: CSV with a header row naming `challenge`
    (required), `points` and `flag` (optional). Blank lines and lines starting with '#' are skipped."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise HumanOpsError(f"no truth file at {p}") from None
    lines = [ln for ln in raw.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise HumanOpsError(f"{p}: empty: expected a CSV header naming 'challenge'")
    rd = csv.DictReader(io.StringIO("\n".join(lines)))
    cols = {(c or "").strip().lower(): c for c in rd.fieldnames or ()}
    if "challenge" not in cols:
        raise HumanOpsError(f"{p}: the header must name a 'challenge' column; got {', '.join(cols) or 'none'}")
    unknown = sorted(set(cols) - {"challenge", "points", "flag"})
    if unknown:
        raise HumanOpsError(f"{p}: unknown column(s): {', '.join(unknown)} (allowed: challenge, points, flag)")
    rows, seen = [], set()
    for n, rec in enumerate(rd, 2):
        cid = (rec.get(cols["challenge"]) or "").strip()
        if not cid:
            raise HumanOpsError(f"{p}: row {n} has no challenge")
        if _norm_id(cid) in seen:
            raise HumanOpsError(f"{p}: row {n}: challenge {cid!r} is listed twice")
        seen.add(_norm_id(cid))
        pts = (rec.get(cols["points"]) or "").strip() if "points" in cols else ""
        try:
            points = float(pts) if pts else None
        except ValueError:
            raise HumanOpsError(f"{p}: row {n}: points {pts!r} is not a number") from None
        flag = (rec.get(cols["flag"]) or "").strip() if "flag" in cols else ""
        rows.append(TruthRow(cid, points, flag or None, n))
    return rows


# ------------------------------------------------------------------------------------------ rendering

def render_card(c: Card, now: float) -> str:
    lines = [f"[{c.id}] {_card_head(c)}  ({c.status}, open {_dur(c.age(now))})",
             f"  ask:  {c.ask}", f"  need: {c.need}"]
    if c.why:
        lines.append(f"  why:  {c.why}")
    if c.source:
        lines.append(f"  from: {c.source}")
    for p in c.candidates:
        lines.append(f"  candidate {p.text} ({p.decimals} decimals){'  ' + p.note if p.note else ''}  {p.map_url}")
    if c.status == "answered":
        lines.append(f"  answer: {c.answer}" + (f"  (by {c.by})" if c.by else ""))
    elif c.status == "dropped":
        lines.append(f"  dropped: {c.reason}" + (f"  (by {c.by})" if c.by else ""))
    return "\n".join(lines)


def render_reconciliation(rep: Reconciliation) -> str:
    s = rep.system
    out = [f"Reconciliation: Game Master record vs {s} (the source of truth)",
           "  " + "  ".join(f"{k}={v}" for k, v in rep.counts().items())]
    if rep.missing:
        out.append(f"\nOn the Game Master record, missing from {s} (confirm these):")
        for it in rep.missing:
            flagged = "  MARKED CONFIRMED HERE BUT ABSENT" if it.done else ""
            out.append(f"  - {confirm_line(it)}{flagged}")
    if rep.extra:
        out.append(f"\nIn {s}, no Game Master record (check who solved it and how):")
        for t in rep.extra:
            out.append(f"  - {t.challenge_id}" + (f", {t.points:g} pts" if t.points is not None else "")
                       + f"  (row {t.line})")
    if rep.flag_mismatch:
        out.append(f"\nFlag differs between the Game Master record and {s}:")
        for it, t in rep.flag_mismatch:
            ours = it.flag or f"sha256 {it.flag_sha256[:12]}..."
            out.append(f"  - {it.challenge_id}: ours {ours} / {s} {t.flag}  (row {t.line})")
    if rep.points_mismatch:
        out.append(f"\nPoints differ ({s} wins):")
        for it, t in rep.points_mismatch:
            out.append(f"  - {it.challenge_id}: ours {it.points:g} / {s} {t.points:g}  (row {t.line})")
    out.append("\nALL AGREE" if rep.clean else "\nACTION NEEDED: see above")
    return "\n".join(out)


_SECTIONS = (
    ("standing", "Before you sleep: human-only, every event day"),
    ("event", "This event"),
    ("card", "Open task cards (out-of-band steps)"),
    ("pin", "OSINT final-pin queue"),
    ("confirm", "Confirm list"),
)


def render_checklist(cl: Checklist) -> str:
    out = [f"# Evening checklist: {cl.event}, for {cl.for_date.isoformat()} ({cl.when})", ""]
    for sec, title in _SECTIONS:
        rows = cl.section(sec)
        if sec in ("card", "pin") and not rows:
            out += [f"## {title}", "", "- none open", ""]
            continue
        if not rows:
            continue
        out += [f"## {title}", ""] + [f"- [ ] {i.text}" for i in rows] + [""]
    return "\n".join(out).rstrip() + "\n"
