"""Pay for the build once (B-008): rank pre-event builds by modeled value per effort, and refuse any
pre-event or in-event build that does not carry an approved ranking record.

    from ctf import buildplan, event
    items = buildplan.load_items("to_build.json")          # to_build-style records
    ranking = buildplan.rank(items, event.load("csctf"), effort_budget=6)
    buildplan.record(ranking)                              # <workdir>/build-plan/ranking.json
    buildplan.require_build("B-012", event.load("csctf"))  # BuildRefused unless approved

Why: build/verify/doc was 65.9% of all dollars across the four 2026 events; CSCTF spent $7,567.60
before the first challenge opened, its sector engines were built before the board was visible and
never invoked, and discretionary builds ran to use up an expiring allowance (analysis
tokens/EFFICIENCY-PLAN.md section 3.1). The master is paid for once; pre-event work defaults to the
doctor and a rehearsal (ctf.preevent); any other pre-event build must be ranked here first and fit
the effort budget the player chose. The default budget is 0, so nothing is approved by default.

Item records (a JSON list, or {"items": [...]}). Unknown keys are ignored (to_build.json carries many):

    id        required, str
    lane      the build lane; to_build.json calls it "category" (either is accepted, lane wins)
    effort    required: S | M | L | XL, or a positive number of effort units
    closes    list of coverage rows the build closes (default [])
    payoff    free text, a number (USD) or {"usd": n}; the first "$n" in text is read as modeled USD
    priority  optional P0..P3
    sectors   optional list of sector names the build targets (also detected in the title)
    automatable, merged_into   honoured when present ("no" / set => skip)

THE NUMBERS ARE MODELED ESTIMATES, NOT MEASURED SAVINGS. value = (coverage rows + modeled USD/100,
or 1 when neither is known) x priority weight x relevance; score = value / effort units.

Relevance comes from the event profile (categories, sectors) or, once visible, the board:
  * cross-cutting lanes (ops, harness, token-efficiency, intake, ...) serve every event: relevance 1;
  * a category lane served by an announced category: relevance 1; categories not announced yet: 0.5
    and the build waits for the board ("after-board");
  * a lane no announced category serves: skip;
  * a sector-targeted build (the CSCTF failure) always waits for the board, unless the board shows it.
Decisions: approved (eligible and inside the effort budget), candidate (eligible, over budget),
after-board, skip. Only "approved" passes the gate.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import math
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from . import ledger, paths
from .event import EventProfile

SCHEMA = 1
ESTIMATE_LABEL = "modeled estimate (to_build payoff text and closes rows; not a measured saving)"
RANKING_DIR = "build-plan"
RANKING_NAME = "ranking.json"

EFFORT_UNITS = {"S": 1.0, "M": 3.0, "L": 8.0, "XL": 20.0}
PRIORITY_WEIGHT = {"P0": 4.0, "P1": 2.0, "P2": 1.0, "P3": 0.5}
USD_PER_POINT = 100.0
UNCATEGORISED_RELEVANCE = 0.5

DECISIONS = ("approved", "candidate", "after-board", "skip")

# Lanes that serve every event regardless of its categories.
GENERAL_LANES = frozenset({
    "engine", "ops", "token-efficiency", "orchestration", "harness", "speed", "submission",
    "writeups", "layer1-intake", "intake",
})

# Lane -> the canonical event categories it serves.
LANE_SERVES = {
    "web": {"web"},
    "forensics": {"forensics"},
    "rev": {"reverse"},
    "reverse": {"reverse"},
    "crypto": {"crypto"},
    "pwn": {"pwn"},
    "osint": {"osint"},
    "network-ics": {"network", "ics"},
    "network": {"network"},
    "ics": {"ics"},
    "stego": {"stego", "forensics", "misc"},
    "mobile": {"mobile"},
    "ml": {"ml"},
    "other": {"misc"},
    "misc": {"misc"},
    "blockchain": {"blockchain"},
    "hardware": {"hardware"},
    "linux": {"linux"},
    "windows": {"windows"},
}

# Event category spellings -> canonical tokens. A spelling not listed whole is read word by word
# ("Metadata Forensics" -> forensics, "Mobile Android" -> mobile); an unknown word stays itself.
_CATEGORY_ALIASES: dict[str, tuple[str, ...]] = {
    "reverse engineering": ("reverse",), "reversing": ("reverse",), "rev": ("reverse",),
    "re": ("reverse",), "binary": ("reverse", "pwn"), "binary exploitation": ("pwn",),
    "exploitation": ("pwn",), "pwnable": ("pwn",), "script analysis": ("reverse",),
    "cryptography": ("crypto",), "steganography": ("stego",), "networking": ("network",),
    "network security": ("network",), "ot": ("ics",), "scada": ("ics",), "ics/ot": ("ics",),
    "machine learning": ("ml",), "ai": ("ml",), "ai/ml": ("ml",), "android": ("mobile",),
    "ios": ("mobile",), "digital forensics": ("forensics",), "dfir": ("forensics",),
    "miscellaneous": ("misc",), "warmups": ("misc",), "warmup": ("misc",),
    "web exploitation": ("web",), "blockchain/web3": ("blockchain",), "web3": ("blockchain",),
}
_KNOWN_TOKENS = frozenset(t for s in LANE_SERVES.values() for t in s)

# Sector words detected in an item's title (word-bounded) when it has no explicit "sectors" field.
SECTOR_WORDS = ("energy", "power", "grid", "telecom", "finance", "banking", "healthcare", "medical",
                "defence", "defense", "space", "satellite", "maritime", "automotive", "aviation",
                "railway", "water")
_SECTOR_ALIASES = {"defense": "defence", "power": "energy", "grid": "energy", "banking": "finance",
                   "medical": "healthcare", "satellite": "space"}

_USD_RE = re.compile(r"\$\s?([0-9][0-9,]*(?:\.[0-9]+)?)")


class BuildPlanError(ValueError):
    """An item file, board file or ranking is missing or invalid. The message names it."""


class BuildRefused(RuntimeError):
    """The build gate refused a build. .decision carries the reason."""

    def __init__(self, decision: "GateDecision"):
        super().__init__(decision.reason)
        self.decision = decision


# ---------------------------------------------------------------------------------------- records

@dataclass(frozen=True)
class Item:
    id: str
    lane: str
    effort: str
    effort_units: float
    closes: int
    payoff_usd: float | None
    payoff_text: str
    priority: str | None
    title: str = ""
    sectors: tuple[str, ...] = ()
    automatable: str | None = None
    merged_into: str | None = None
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Ranked:
    rank: int
    id: str
    title: str
    lane: str
    decision: str
    reason: str
    score: float
    value: float
    relevance: float
    effort: str
    effort_units: float
    closes: int
    payoff_usd: float | None
    priority: str | None
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Ranking:
    event: str
    created: float
    effort_budget: float
    board_visible: bool
    items_source: str | None
    items_sha256: str | None
    board_source: str | None
    board_sha256: str | None
    entries: tuple[Ranked, ...]
    estimate: str = ESTIMATE_LABEL
    schema: int = SCHEMA

    def get(self, item_id: str) -> Ranked | None:
        return next((e for e in self.entries if e.id == item_id), None)

    def approved(self) -> list[Ranked]:
        return [e for e in self.entries if e.decision == "approved"]

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, indent=1, sort_keys=False)

    @classmethod
    def from_json(cls, s: str, *, src: str = "<ranking>") -> "Ranking":
        try:
            d = json.loads(s)
        except json.JSONDecodeError as e:
            raise BuildPlanError(f"{src}: not JSON: {e}") from None
        if not isinstance(d, dict) or d.get("schema") != SCHEMA:
            raise BuildPlanError(f"{src}: not a schema-{SCHEMA} build ranking")
        try:
            entries = tuple(Ranked(**{**e, "dependencies": tuple(e.get("dependencies", ()))})
                            for e in d.pop("entries"))
            return cls(entries=entries, **d)
        except (TypeError, KeyError) as e:
            raise BuildPlanError(f"{src}: malformed ranking: {e}") from None


# ---------------------------------------------------------------------------------------- loading

def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def canon_categories(c: str) -> frozenset[str]:
    """Canonical category tokens for one event/board category spelling."""
    k = " ".join(str(c).strip().lower().split())
    if k in _CATEGORY_ALIASES:
        return frozenset(_CATEGORY_ALIASES[k])
    if k in _KNOWN_TOKENS:
        return frozenset({k})
    out: set[str] = set()
    for w in k.replace("/", " ").split():
        if w in _CATEGORY_ALIASES:
            out.update(_CATEGORY_ALIASES[w])
        elif w in _KNOWN_TOKENS:
            out.add(w)
    return frozenset(out or {k})


def _canon_sector(s: str) -> str:
    k = str(s).strip().lower()
    return _SECTOR_ALIASES.get(k, k)


def parse_payoff_usd(payoff: Any) -> float | None:
    """The modeled USD figure in a payoff: a number, {"usd": n}, or the first "$n" in text."""
    if payoff is None or isinstance(payoff, bool):
        return None
    if isinstance(payoff, (int, float)):
        return float(payoff)
    if isinstance(payoff, dict):
        v = payoff.get("usd")
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    m = _USD_RE.search(str(payoff))
    return float(m.group(1).replace(",", "")) if m else None


def _effort_units(raw: Any, where: str) -> tuple[str, float]:
    if isinstance(raw, str) and raw.strip().upper() in EFFORT_UNITS:
        e = raw.strip().upper()
        return e, EFFORT_UNITS[e]
    if isinstance(raw, (int, float)) and not isinstance(raw, bool) and raw > 0:
        return f"{float(raw):g}u", float(raw)
    raise BuildPlanError(f"{where}.effort: expected one of {', '.join(EFFORT_UNITS)} or a positive "
                         f"number, got {raw!r}")


def parse_item(rec: Any, where: str = "item") -> Item:
    if not isinstance(rec, dict):
        raise BuildPlanError(f"{where}: expected an object, got {type(rec).__name__}")
    iid = rec.get("id")
    if not isinstance(iid, str) or not iid.strip():
        raise BuildPlanError(f"{where}.id: required (a non-empty string)")
    where = f"{where} ({iid})"
    lane = rec.get("lane", rec.get("category"))
    if not isinstance(lane, str) or not lane.strip():
        raise BuildPlanError(f"{where}.lane: required (or 'category', as in to_build.json)")
    if "effort" not in rec:
        raise BuildPlanError(f"{where}.effort: required")
    effort, units = _effort_units(rec["effort"], where)
    closes = rec.get("closes", [])
    if not isinstance(closes, list):
        raise BuildPlanError(f"{where}.closes: expected a list of coverage rows")
    prio = rec.get("priority")
    if prio is not None and prio not in PRIORITY_WEIGHT:
        raise BuildPlanError(f"{where}.priority: expected one of {', '.join(PRIORITY_WEIGHT)}, got {prio!r}")
    sectors = rec.get("sectors", [])
    if not isinstance(sectors, list) or not all(isinstance(s, str) for s in sectors):
        raise BuildPlanError(f"{where}.sectors: expected a list of strings")
    deps = rec.get("dependencies", [])
    payoff = rec.get("payoff")
    return Item(
        id=iid.strip(), lane=lane.strip().lower(), effort=effort, effort_units=units,
        closes=len(closes), payoff_usd=parse_payoff_usd(payoff),
        payoff_text="" if payoff is None else str(payoff), priority=prio,
        title=str(rec.get("title", "")), sectors=tuple(_canon_sector(s) for s in sectors),
        automatable=rec.get("automatable"), merged_into=rec.get("merged_into") or None,
        dependencies=tuple(str(d) for d in deps) if isinstance(deps, list) else (),
    )


def load_items(path: str | Path) -> list[Item]:
    p = Path(path)
    if not p.is_file():
        raise BuildPlanError(f"item file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise BuildPlanError(f"{p}: not JSON: {e}") from None
    if isinstance(data, dict) and "items" in data:
        data = data["items"]
    if not isinstance(data, list):
        raise BuildPlanError(f"{p}: expected a list of item records (or {{'items': [...]}})")
    items = [parse_item(r, f"{p.name}[{i}]") for i, r in enumerate(data)]
    seen: set[str] = set()
    for it in items:
        if it.id in seen:
            raise BuildPlanError(f"{p}: duplicate item id {it.id}")
        seen.add(it.id)
    return items


@dataclass(frozen=True)
class Board:
    """What the visible board shows: canonical category -> challenge count, and sector words."""
    categories: dict[str, int]
    text: str

    def shows_sector(self, sector: str) -> bool:
        words = {sector} | {k for k, v in _SECTOR_ALIASES.items() if v == sector}
        return any(re.search(rf"\b{re.escape(w)}\b", self.text) for w in words)


def load_board(path: str | Path) -> Board:
    """A board file: a JSON list of challenges, each {"category": str, "name"?, "description"?, "tags"?}
    (or {"challenges": [...]}, the shape `ctf list --json` style dumps use)."""
    p = Path(path)
    if not p.is_file():
        raise BuildPlanError(f"board file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise BuildPlanError(f"{p}: not JSON: {e}") from None
    if isinstance(data, dict) and "challenges" in data:
        data = data["challenges"]
    if not isinstance(data, list) or not data:
        raise BuildPlanError(f"{p}: expected a non-empty list of challenges")
    cats: dict[str, int] = {}
    text: list[str] = []
    for i, ch in enumerate(data):
        if not isinstance(ch, dict) or not isinstance(ch.get("category"), str):
            raise BuildPlanError(f"{p}[{i}].category: required (a string)")
        for c in canon_categories(ch["category"]):
            cats[c] = cats.get(c, 0) + 1
        tags = ch.get("tags") or []
        text.append(" ".join([ch["category"], str(ch.get("name", "")), str(ch.get("description", "")),
                              " ".join(map(str, tags)) if isinstance(tags, list) else str(tags)]))
    return Board(categories=cats, text=" ".join(text).lower())


# ---------------------------------------------------------------------------------------- ranking

def _item_sectors(it: Item) -> tuple[str, ...]:
    if it.sectors:
        return it.sectors
    title = it.title.lower()
    found = {_canon_sector(w) for w in SECTOR_WORDS if re.search(rf"\b{w}\b", title)}
    return tuple(sorted(found))


def _relevance(it: Item, profile: EventProfile, board: Board | None) -> tuple[float, str, str]:
    """(relevance, eligibility, reason). eligibility is 'eligible', 'after-board' or 'skip'."""
    if it.merged_into:
        return 0.0, "skip", f"merged into {it.merged_into}"
    if str(it.automatable or "").lower() == "no":
        return 0.0, "skip", "not automatable: a build runner cannot build it"
    sectors = _item_sectors(it)
    if sectors:
        if board is not None:
            hit = [s for s in sectors if board.shows_sector(s)]
            if hit:
                return 1.0, "eligible", f"board shows sector {', '.join(hit)}"
            return 0.0, "skip", f"sector {', '.join(sectors)} not on the board"
        announced = {_canon_sector(s) for s in profile.sectors}
        hit = [s for s in sectors if s in announced]
        if hit:
            return UNCATEGORISED_RELEVANCE, "after-board", (
                f"sector {', '.join(hit)} is announced but sector builds wait for the board")
        return 0.0, "skip", f"sector {', '.join(sectors)} not in the event profile"
    if it.lane in GENERAL_LANES:
        return 1.0, "eligible", f"cross-cutting lane '{it.lane}' serves every event"
    serves = LANE_SERVES.get(it.lane, {it.lane})
    if board is not None:
        counts = [board.categories.get(c, 0) for c in serves]
        n = max(counts)
        if n:
            top = max(board.categories.values())
            rel = 0.5 + 0.5 * (n / top)
            return rel, "eligible", f"board has {n} challenge(s) in a category lane '{it.lane}' serves"
        return 0.0, "skip", f"no board category served by lane '{it.lane}'"
    announced = {t for c in profile.categories for t in canon_categories(c)}
    if not announced:
        return UNCATEGORISED_RELEVANCE, "after-board", "event categories not announced; wait for the board"
    if serves & announced:
        return 1.0, "eligible", f"lane '{it.lane}' serves announced {', '.join(sorted(serves & announced))}"
    return 0.0, "skip", f"lane '{it.lane}' serves no announced category"


def value_of(it: Item) -> float:
    """Modeled value points (unweighted by relevance): rows + USD/100, or 1 when neither is known."""
    base = it.closes + (it.payoff_usd or 0.0) / USD_PER_POINT
    if base <= 0:
        base = 1.0
    return base * PRIORITY_WEIGHT.get(it.priority or "", 1.0)


def rank(items: Iterable[Item], profile: EventProfile, *, effort_budget: float = 0.0,
         board: Board | None = None, items_source: str | Path | None = None,
         board_source: str | Path | None = None, now: float | None = None) -> Ranking:
    """Rank items by modeled value per effort and decide each one. Approval walks the eligible items
    in score order and approves each that still fits the remaining effort budget."""
    if not isinstance(effort_budget, (int, float)) or isinstance(effort_budget, bool) or effort_budget < 0 \
            or math.isnan(effort_budget):
        raise BuildPlanError(f"effort budget must be a number >= 0, got {effort_budget!r}")
    scored = []
    for it in items:
        rel, elig, why = _relevance(it, profile, board)
        val = value_of(it) * rel
        scored.append((val / it.effort_units, val, rel, elig, why, it))
    scored.sort(key=lambda t: (-t[0], t[5].effort_units, t[5].id))
    left = float(effort_budget)
    out = []
    for n, (score, val, rel, elig, why, it) in enumerate(scored, 1):
        if elig == "eligible":
            if it.effort_units <= left:
                left -= it.effort_units
                decision, reason = "approved", f"{why}; fits budget ({left:g} units left)"
            else:
                decision, reason = "candidate", f"{why}; over the effort budget ({left:g} units left)"
        else:
            decision, reason = elig, why
        out.append(Ranked(rank=n, id=it.id, title=it.title, lane=it.lane, decision=decision,
                          reason=reason, score=round(score, 4), value=round(val, 4),
                          relevance=round(rel, 4), effort=it.effort, effort_units=it.effort_units,
                          closes=it.closes, payoff_usd=it.payoff_usd, priority=it.priority,
                          dependencies=it.dependencies))
    ip = Path(items_source) if items_source else None
    bp = Path(board_source) if board_source else None
    return Ranking(event=profile.slug, created=time.time() if now is None else now,
                   effort_budget=float(effort_budget), board_visible=board is not None,
                   items_source=str(ip) if ip else None,
                   items_sha256=_sha256(ip) if ip and ip.is_file() else None,
                   board_source=str(bp) if bp else None,
                   board_sha256=_sha256(bp) if bp and bp.is_file() else None,
                   entries=tuple(out))


# ---------------------------------------------------------------------------------------- record

def ranking_path(workdir: Path | None = None) -> Path:
    return (paths.workdir() if workdir is None else Path(workdir)) / RANKING_DIR / RANKING_NAME


def record(ranking: Ranking, *, workdir: Path | None = None) -> Path:
    """Write the ranking (atomically) and log a build_plan.rank ledger event."""
    p = ranking_path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(ranking.to_json() + "\n", encoding="utf-8")
    os.replace(tmp, p)
    ledger.append("build_plan.rank", workdir=workdir, slug=ranking.event,
                  approved=[e.id for e in ranking.approved()], effort_budget=ranking.effort_budget,
                  board_visible=ranking.board_visible, items_sha256=ranking.items_sha256,
                  estimate=ESTIMATE_LABEL)
    return p


def load_ranking(workdir: Path | None = None) -> Ranking:
    p = ranking_path(workdir)
    if not p.is_file():
        raise BuildPlanError(f"no build ranking recorded at {p}; run: python -m ctf build-plan rank "
                             f"--items <to_build.json> --effort-budget <units> --record")
    return Ranking.from_json(p.read_text(encoding="utf-8"), src=str(p))


# ---------------------------------------------------------------------------------------- the gate

@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    item_id: str
    phase: str              # pre-event | in-event | post-event
    reason: str
    entry: Ranked | None = None


def _as_utc(d: _dt.date | _dt.datetime, *, end: bool) -> _dt.datetime:
    if isinstance(d, _dt.datetime):
        return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)
    t = _dt.time.max if end else _dt.time.min
    return _dt.datetime.combine(d, t, tzinfo=_dt.timezone.utc)


def phase_of(profile: EventProfile, now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.timezone.utc)
    if now < _as_utc(profile.start, end=False):
        return "pre-event"
    if now <= _as_utc(profile.end, end=True):
        return "in-event"
    return "post-event"


def check_build(item_id: str, profile: EventProfile, *, workdir: Path | None = None,
                now: _dt.datetime | None = None, log: bool = True,
                master: Path | None = None) -> GateDecision:
    """The no-allowance-burn rule, called by the build runner before it starts a to_build item.

    Pre-event and in-event, a build runs only when the recorded ranking for this event approved it
    (in-event, the ranking must have been made with the board visible). Post-event, promotion comes
    first: a build runs only once B-038's fold-audit passes for this event (every live fix recorded
    in `<master>/events/<slug>/promotion.json` reached the master HEAD); no record, or an unfolded
    fix, refuses it with the audit's reason. Every decision is logged as a build_plan.check ledger
    event."""
    ph = phase_of(profile, now)
    entry = None
    if ph == "post-event":
        dec = _post_event(item_id, profile, master)
    else:
        try:
            rk = load_ranking(workdir)
        except BuildPlanError as e:
            dec = GateDecision(False, item_id, ph, f"refused: {e}")
        else:
            entry = rk.get(item_id)
            if rk.event != profile.slug:
                dec = GateDecision(False, item_id, ph, f"refused: the recorded ranking is for event "
                                                       f"'{rk.event}', not '{profile.slug}'; re-rank")
            elif entry is None:
                dec = GateDecision(False, item_id, ph, f"refused: {item_id} has no ranking record; add "
                                                       f"it to the item file and re-rank")
            elif ph == "in-event" and not rk.board_visible:
                dec = GateDecision(False, item_id, ph, "refused: in-event builds must be ranked against "
                                                       "the visible board (rank --board <file> --record)",
                                   entry)
            elif entry.decision != "approved":
                dec = GateDecision(False, item_id, ph, f"refused: ranked #{entry.rank} '{entry.decision}' "
                                                       f"({entry.reason})", entry)
            else:
                dec = GateDecision(True, item_id, ph, f"approved: ranked #{entry.rank}, score "
                                                      f"{entry.score:g} ({ESTIMATE_LABEL})", entry)
    if log:
        ledger.append("build_plan.check", workdir=workdir, item=item_id, slug=profile.slug,
                      phase=dec.phase, allowed=dec.allowed, reason=dec.reason)
    return dec


def _post_event(item_id: str, profile: EventProfile, master: Path | None) -> GateDecision:
    """Post-event: fold first (B-038). Allowed only when the event's fold-audit passes against the
    master HEAD, so no new build lands while a live fix from the event is still unfolded."""
    from . import foldaudit
    from .promote import PromoteError
    try:
        res = foldaudit.audit(profile.slug, master=master, log=False)
    except PromoteError as e:
        return GateDecision(False, item_id, "post-event", f"refused: fold-audit cannot pass: {e}")
    if not res.passed:
        bad = res.failures()
        return GateDecision(False, item_id, "post-event",
                            f"refused: fold-audit fails ({len(bad)} live fix(es) not in the master, "
                            f"first: {bad[0].key}: {bad[0].reason}); promote them first "
                            f"(python -m ctf promote show {profile.slug})")
    return GateDecision(True, item_id, "post-event",
                        f"post-event: fold-audit passed ({len(res.findings)} recorded change(s) reached "
                        f"{res.target_commit[:12]})")


def require_build(item_id: str, profile: EventProfile, **kw: Any) -> GateDecision:
    dec = check_build(item_id, profile, **kw)
    if not dec.allowed:
        raise BuildRefused(dec)
    return dec
