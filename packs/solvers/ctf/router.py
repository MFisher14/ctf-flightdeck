"""Per-role and per-difficulty model router (B-201): which model, reasoning effort and speed tier an
agent launches on, by its work role and the challenge's difficulty. Pure: no model is called, nothing is
launched, nothing is written.

    from ctf import router
    r = router.Router.from_profile(profile)              # validated against tools/ledger/pricing.json
    route = r.resolve("solve", "hard", category="pwn")   # Route(model, effort, tier, budget_usd, ...)
    route = r.resolve("verify", harness="claude")        # a launcher asks for its own harness
    r.roster("solve", "medium")                          # escalation order (ctf/escalation.py)
    r.table()                                            # every role x difficulty

Why. Model choice did not follow the work in the four 2026 events: mechanical verify, audit and doc
roles ran on the top model, Codex mains ran at effort ultra on every challenge, long local CPU searches
ran at max reasoning and ultrafast was used for bulk mechanical build (to_build B-201). The router puts
the choice in one table, per event, in the profile's optional [routing] table (ctf/event.py Routing).

Resolution of (role, difficulty, harness, category):

  * difficulty: the asked one, else routing.default_difficulty. When routing.top_categories is set, a
    solve at "hard" whose category is known and not listed is routed as "medium" (the top tier is for
    pwn, crypto and OSINT reasoning, B-201); an unknown category keeps the asked difficulty.
  * rules: every [[routing.route]] whose role, difficulty and harness match (or are "*"). The model,
    with its tier and budget_usd, comes from the most specific matching rule that names a model; the
    effort from the most specific one that names an effort (harness 4, role 2, difficulty 1). A rule
    with a harness only matches a launch on that harness.
  * built-in defaults, for whatever no rule names (B-095, B-096, B-097):
      - model: models.primary; role "doc" -> models.docs; role "verify" -> routing.verify_candidate
        only once an approving `ab_verify` ledger record names it (tools/ledger/ab_verify.py
        chosen_verify_model), else models.primary. With no A/B record verify stays on the primary.
      - effort: models.effort (B-095's launch-pinned base) stepped by DIFFICULTY_STEPS: warmup one tier
        below, easy and medium at the base, hard one tier up (where the B-095 ramp's second agent
        starts). Clamped to EFFORT_LEVELS.
      - tier: "default" (the standard service tier; B-009 keeps the fast tiers off).
  * verify hold (B-096): a verify route onto any model other than models.primary, from a rule or the
    candidate, is held on models.primary until an approving `ab_verify` record names that model. The
    hold is visible in Route.notes, never silent.
  * harness: a launcher passes its harness. When the routed model belongs to the other harness, the
    route names no model (None) and says so in Route.notes; the effort still applies. The launchers then
    leave the CLI's default model in place, loudly (tools/route_launch.py).

Speed tiers (B-009, B-033). A rule's tier must be priced for its model (Claude: "default", plus "fast"
when the model's row has a fast_multiplier; Codex: the keys of its tier_multiplier). Any tier other than
"default" needs an explicit budget_usd in the rule (ctf/event.py refuses it otherwise); the launcher
then refuses the tier unless the run is budget-gated and metered, and stops the agent once it has spent
budget_usd (tools/launch_gate.py Gate.agent_cap_usd).

Validation (Router(...)): every model the router can return (rules, primary, fallback, docs,
verify_candidate) must be in tools/ledger/pricing.json, a rule's harness must be its model's harness and
its tier must be priced for it. Problems are collected and raised together as RouterError.

`ctf.router` imports `tools.ledger` (the price table, the A/B gate) lazily inside the calls that need
them; an ImportError is a named RouterError (docs/CONTRACTS.md section 11).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import ledger as _ledger
from .event import (DEFAULT_TIER, EFFORT_LEVELS, ROUTE_ANY, ROUTE_DIFFICULTIES, ROUTE_HARNESSES,
                    EventProfile, RouteRule, Routing)
from .stages import SPEND_CATEGORIES

ROLES = SPEND_CATEGORIES
DIFFICULTIES = ROUTE_DIFFICULTIES
HARNESSES = ROUTE_HARNESSES
# B-095's ramp applied to difficulty: tiers above (+) or below (-) the profile's base effort.
DIFFICULTY_STEPS = {"warmup": -1, "easy": 0, "medium": 0, "hard": 1}
TOP_DIFFICULTY = "hard"
TOP_FALLBACK_DIFFICULTY = "medium"


class RouterError(ValueError):
    """The routing table cannot be used (an unpriced model, a tier the model has not, a bad role)."""


@dataclass(frozen=True)
class Route:
    role: str
    difficulty: str               # the difficulty routed (after the top_categories rule)
    model: str | None             # None: no route names a model for the asked harness
    harness: str | None           # the model's harness (None with no model)
    effort: str
    tier: str = DEFAULT_TIER
    budget_usd: float | None = None
    model_rule: int | None = None     # index of the [[routing.route]] that gave the model; None: default
    effort_rule: int | None = None    # same, for the effort
    category: str | None = None
    asked_difficulty: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def speed_tier(self) -> bool:
        return self.tier != DEFAULT_TIER

    @property
    def source(self) -> str:
        """"rule:N" for the rule that gave the model (else the effort), "default" for neither."""
        n = self.model_rule if self.model_rule is not None else self.effort_rule
        return "default" if n is None else f"rule:{n}"

    def ledger_fields(self) -> dict:
        """The fields a launch records on agent_launch (with `role`, which the gate writes). `effort` is
        the route's; tools/route_launch.py record_route replaces it with the effort actually launched
        (an explicit --effort wins), which the escalator reads back as the ramp's base."""
        f: dict = {"difficulty": self.difficulty, "effort": self.effort, "tier": self.tier,
                   "route": self.source}
        if self.category:
            f["category"] = self.category
        if self.budget_usd is not None:
            f["tier_budget_usd"] = self.budget_usd
        return f

    def to_dict(self) -> dict:
        return {"role": self.role, "difficulty": self.difficulty, "asked_difficulty": self.asked_difficulty,
                "category": self.category, "model": self.model, "harness": self.harness,
                "effort": self.effort, "tier": self.tier, "budget_usd": self.budget_usd,
                "source": self.source, "notes": list(self.notes)}


# ----------------------------------------------------------------------------- prices

def load_prices(path: str | Path | None = None) -> dict:
    """tools/ledger/pricing.json (lazy import; a missing tools package is a named RouterError)."""
    try:
        from tools.ledger import pricing as _pricing
    except ImportError as e:
        raise RouterError(f"the price table (tools.ledger.pricing) cannot be imported: {e}; run from the "
                          "repo root") from None
    try:
        return _pricing.load_prices(path)
    except _pricing.PricingError as e:
        raise RouterError(str(e)) from None


def model_harness(model: str, prices: dict) -> str:
    """"claude" or "codex": the pricing section that prices `model`. RouterError when neither does."""
    hits = [h for h in HARNESSES if model in (prices.get(h) or {})]
    if not hits:
        raise RouterError(f"model {model!r} is not in tools/ledger/pricing.json (add its price first)")
    if len(hits) > 1:
        raise RouterError(f"model {model!r} is priced under both {' and '.join(hits)}")
    return hits[0]


def tiers_for(model: str, prices: dict) -> tuple[str, ...]:
    """The speed tiers pricing.json prices for `model`, DEFAULT_TIER first."""
    h = model_harness(model, prices)
    row = prices[h][model]
    if h == "claude":
        return (DEFAULT_TIER, "fast") if "fast_multiplier" in row else (DEFAULT_TIER,)
    tiers = list((row.get("tier_multiplier") or {DEFAULT_TIER: 1}).keys())
    return tuple([DEFAULT_TIER] + [t for t in tiers if t != DEFAULT_TIER])


def _step(base: str, steps: int) -> str:
    i = EFFORT_LEVELS.index(base)
    return EFFORT_LEVELS[max(0, min(len(EFFORT_LEVELS) - 1, i + steps))]


def _dedup(models: Iterable[str | None]) -> list[str]:
    out: list[str] = []
    for m in models:
        m = (m or "").strip()
        if m and m not in out:
            out.append(m)
    return out


# ----------------------------------------------------------------------------- the router

class Router:
    """The routing table of one event profile, validated against the price table. `records` are the
    event ledger's records (read for the B-096 A/B gate); when None they are read from `workdir`
    (default: the event's workdir) at construction, and a ledger that cannot be read (a corrupt line,
    an OSError) is a RouterError naming the ledger file."""

    def __init__(self, profile: EventProfile, *, prices: dict | None = None,
                 records: Iterable[dict] | None = None, workdir: Path | None = None):
        self.profile = profile
        self.routing: Routing = profile.routing if profile.routing is not None else Routing()
        self.opted_in = profile.routing is not None
        self.prices = prices if prices is not None else load_prices()
        if records is None:
            from . import paths as _paths
            wd = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
            try:
                records = list(_ledger.read(wd))
            except (ValueError, OSError) as e:
                raise RouterError(f"the event ledger {_ledger.path(wd)} cannot be read for the B-096 "
                                  f"A/B gate: {e}") from None
        self._ab = [r for r in records if isinstance(r, dict) and r.get("event") == "ab_verify"]
        self._validate()

    @classmethod
    def from_profile(cls, profile: EventProfile, **kw) -> "Router":
        return cls(profile, **kw)

    # ------------------------------------------------------------------ validation
    def _validate(self) -> None:
        problems: list[str] = []
        m = self.profile.models
        named = [("models.primary", m.primary), *((f"models.fallback[{i}]", x) for i, x in
                                                   enumerate(m.fallback)), ("models.docs", m.docs)]
        if self.routing.verify_candidate:
            named.append(("routing.verify_candidate", self.routing.verify_candidate))
        for where, model in named:
            try:
                model_harness(model, self.prices)
            except RouterError as e:
                problems.append(f"{where}: {e}")
        for r in self.routing.rules:
            where = f"routing.route[{r.index}]"
            if r.role != ROUTE_ANY and r.role not in ROLES:
                problems.append(f"{where}: unknown role {r.role!r}")
            if r.model is None:
                continue
            try:
                h = model_harness(r.model, self.prices)
            except RouterError as e:
                problems.append(f"{where}: {e}")
                continue
            if r.harness != ROUTE_ANY and r.harness != h:
                problems.append(f"{where}: harness {r.harness!r} but model {r.model!r} is a {h} model")
            tiers = tiers_for(r.model, self.prices)
            if r.tier not in tiers:
                problems.append(f"{where}: tier {r.tier!r} is not priced for {r.model!r} "
                                f"(priced: {', '.join(tiers)})")
            if r.tier != DEFAULT_TIER and r.budget_usd is None:
                problems.append(f"{where}: tier {r.tier!r} needs an explicit budget_usd (B-033)")
        if problems:
            src = self.profile.path or self.profile.slug
            raise RouterError(f"{src}: [routing] is not usable: " + "; ".join(problems))

    # ------------------------------------------------------------------ the B-096 gate
    def verify_approved(self, model: str) -> bool:
        """True when an approving `ab_verify` record names `model` (B-096): verify may then run on it."""
        try:
            from tools.ledger import ab_verify as _ab
        except ImportError as e:
            raise RouterError(f"the A/B gate (tools.ledger.ab_verify) cannot be imported: {e}") from None
        primary = self.profile.models.primary
        return _ab.chosen_verify_model(self._ab, primary=primary, candidate=model) == model

    # ------------------------------------------------------------------ resolving
    def _difficulty(self, role: str, difficulty: str | None, category: str | None) -> tuple[str, list[str]]:
        notes: list[str] = []
        d = difficulty if difficulty is not None else self.routing.default_difficulty
        if d not in DIFFICULTIES:
            raise RouterError(f"unknown difficulty {d!r}; one of: {', '.join(DIFFICULTIES)}")
        top = self.routing.top_categories
        if (role == "solve" and d == TOP_DIFFICULTY and top and category
                and category.strip().lower() not in top):
            notes.append(f"category {category!r} is not in routing.top_categories "
                         f"({', '.join(top)}): routed as {TOP_FALLBACK_DIFFICULTY}")
            d = TOP_FALLBACK_DIFFICULTY
        return d, notes

    def _matching(self, role: str, difficulty: str, harness: str | None) -> list[RouteRule]:
        out = [r for r in self.routing.rules
               if r.role in (role, ROUTE_ANY) and r.difficulty in (difficulty, ROUTE_ANY)
               and (r.harness == ROUTE_ANY or r.harness == harness)]
        return sorted(out, key=lambda r: -r.specificity)

    def _default_model(self, role: str, notes: list[str]) -> str:
        m = self.profile.models
        if role == "doc":
            return m.docs
        if role == "verify" and self.routing.verify_candidate:
            cand = self.routing.verify_candidate
            if cand != m.primary and not self.verify_approved(cand):
                notes.append(f"verify stays on {m.primary}: no approving ab_verify record names "
                             f"{cand} (B-096)")
                return m.primary
            return cand
        return m.primary

    def resolve(self, role: str, difficulty: str | None = None, *, harness: str | None = None,
                category: str | None = None) -> Route:
        """The route for one launch. `harness` is the launcher's ("claude" | "codex") or None for a
        harness-free answer (the escalation roster). Raises RouterError on an unknown role,
        difficulty or harness."""
        if role not in ROLES:
            raise RouterError(f"unknown role {role!r}; one of: {', '.join(ROLES)}")
        if harness is not None and harness not in HARNESSES:
            raise RouterError(f"unknown harness {harness!r}; one of: {', '.join(HARNESSES)}")
        cat = category.strip() if isinstance(category, str) and category.strip() else None
        d, notes = self._difficulty(role, difficulty, cat)
        rules = self._matching(role, d, harness)
        m_rule = next((r for r in rules if r.model is not None), None)
        e_rule = next((r for r in rules if r.effort is not None), None)

        effort = e_rule.effort if e_rule is not None else _step(self.profile.models.effort,
                                                                DIFFICULTY_STEPS[d])
        if m_rule is not None:
            model, tier, budget = m_rule.model, m_rule.tier, m_rule.budget_usd
        else:
            model, tier, budget = self._default_model(role, notes), DEFAULT_TIER, None
        primary = self.profile.models.primary
        if role == "verify" and m_rule is not None and model != primary and not self.verify_approved(model):
            notes.append(f"verify held on {primary}: rule {m_rule.index} names {model} but no approving "
                         f"ab_verify record does (B-096)")
            model, tier, budget = primary, DEFAULT_TIER, None
        model_h = model_harness(model, self.prices)
        if harness is not None and model_h != harness:
            notes.append(f"no route names a {harness} model for {role}/{d} (it routes to {model}, a "
                         f"{model_h} model): the {harness} CLI's default model applies")
            model, model_h, tier, budget = None, None, DEFAULT_TIER, None
        return Route(role=role, difficulty=d, model=model, harness=model_h, effort=effort, tier=tier,
                     budget_usd=budget, model_rule=m_rule.index if (m_rule is not None and model is not None
                                                                     and model == m_rule.model) else None,
                     effort_rule=e_rule.index if e_rule is not None else None, category=cat,
                     asked_difficulty=difficulty, notes=tuple(notes))

    def roster(self, role: str = "solve", difficulty: str | None = None, *,
               category: str | None = None) -> list[str]:
        """The escalation order for a challenge (ctf/escalation.py): the routed model at this difficulty,
        then the models routed at each harder difficulty (each harness's own rule after the generic
        one), then models.primary and models.fallback. No duplicates."""
        start, _ = self._difficulty(role, difficulty, category)
        out: list[str | None] = []
        for d in DIFFICULTIES[DIFFICULTIES.index(start):]:
            for h in (None, *HARNESSES):
                out.append(self.resolve(role, d, harness=h, category=category).model)
        m = self.profile.models
        return _dedup([*out, m.primary, *m.fallback])

    def table(self, *, harness: str | None = None) -> list[Route]:
        """Every role x difficulty, for one harness or harness-free."""
        return [self.resolve(role, d, harness=harness) for role in ROLES for d in DIFFICULTIES]
