"""B-100: detect the safety-classifier model fallback in Claude Code session logs, and price it.

A safety classifier can move a session that asked for the primary model (Opus 5.5) onto a fallback
model (Opus 4.8), where cache reads cost 2.5x. That is the classifier's decision. This module only
SEES and PRICES it: it never switches models, relaunches, rephrases or retries anything, and nothing
here should be used to dodge the classifier. The sanctioned way to end the fallback is the player's
cyber verified profile (BUILD-PLAN O-3), recorded in the event profile's [models] table.

    from tools.ledger import fallback
    rep = fallback.detect([log, ...], primary="claude-opus-5-5", fallback=["claude-opus-4-8"])
    rep.fell_back, rep.premium_usd, rep.sessions[0].stuck
    fallback.record(rep, workdir=..., cyber_verified="unknown")   # one model_fallback ledger event per session
    fallback.rate_ratios(prices, "claude-opus-5-5", "claude-opus-4-8")   # per token class

Each log is one session (main or subagent JSONL). Usage rows come from tools.ledger.scan (the same
de-duplication by message.id as the pricer). A session "fell back" when any of its responses came
from a fallback model; it is "stuck" when no primary-model response follows the first fallback one.
A session made only of fallback responses is reported as fallback_only: from the log alone it cannot
be told apart from a session someone started on that model on purpose. Model ids are matched exactly:
a response on any other id (a dated or suffixed spelling of a fallback model, a subagent's model) is
counted in other_responses / other_models, never as primary or fallback, and the CLI warns about it.
A primary response with the same timestamp as the first fallback one is not a return to the primary.

The premium is what the fallback responses cost at the fallback's real rates minus what the same
tokens cost at the primary's rates. Spend fed to the budget meter is already priced at the real
(fallback) rates by tools.ledger.live, so caps see the true cost; this module reports how much of it
is the fallback's premium.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import pricing, scan

LEDGER_EVENT = "model_fallback"
TOKEN_CLASSES = ("input", "cache_read", "cache_5m", "cache_1h", "output")

GUIDANCE = (
    "A safety classifier moved this work off {primary} onto {fallback}. That is the classifier's call, "
    "not a fault to work around: do not switch models, rephrase, split or relaunch work to dodge it. "
    "Fallback spend is charged at its real rates (the budget caps already see it). The sanctioned fix "
    "is the cyber verified profile (BUILD-PLAN O-3).")
HUMAN_STEP = (
    "Human step (the player only): settle the cyber verified profile for the Claude account the event "
    "runs on with Anthropic (BUILD-PLAN O-3), then record the outcome in events/{slug}/event.toml "
    "[models] cyber_verified = \"requested\" | \"granted\" | \"denied\". Until it is granted, budget "
    "for the fallback rates.")
OTHER_MODELS = (
    "{n} response(s) on {models}: neither {primary} nor a listed fallback, so not judged. Model ids "
    "match exactly; if one is a dated or suffixed spelling of a fallback model, pass it with --fallback (it needs a price in tools/ledger/pricing.json).")
GRANTED_BUT_FELL_BACK = (
    "The profile records cyber_verified = \"granted\" but sessions still fell back: the verified "
    "profile may not apply to this account, organisation or harness. Confirm with Anthropic; do not "
    "work around it.")


class FallbackError(ValueError):
    """A log cannot be judged (no Claude usage in it, unreadable timestamps, bad model list)."""


def _when(ts) -> _dt.datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        d = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)


@dataclass
class SessionFallback:
    log: str
    primary_responses: int = 0
    fallback_responses: int = 0
    other_responses: int = 0
    undated_responses: int = 0
    first_ts: str | None = None
    first_primary_ts: str | None = None
    first_fallback_ts: str | None = None
    primary_after_fallback: int = 0
    fallback_models: list[str] = field(default_factory=list)
    other_models: list[str] = field(default_factory=list)
    fallback_usd: float = 0.0
    at_primary_usd: float = 0.0

    @property
    def fell_back(self) -> bool:
        return self.fallback_responses > 0

    @property
    def fallback_only(self) -> bool:
        return self.fell_back and self.primary_responses == 0

    @property
    def stuck(self) -> bool:
        """Fell back and never returned to the primary model afterwards."""
        return self.fell_back and self.primary_after_fallback == 0

    @property
    def premium_usd(self) -> float:
        return self.fallback_usd - self.at_primary_usd

    @property
    def minutes_to_fallback(self) -> float | None:
        a, b = _when(self.first_ts), _when(self.first_fallback_ts)
        if a is None or b is None or self.fallback_only:
            return None
        return (b - a).total_seconds() / 60.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(fell_back=self.fell_back, fallback_only=self.fallback_only, stuck=self.stuck,
                 premium_usd=round(self.premium_usd, 6), minutes_to_fallback=self.minutes_to_fallback)
        return d


@dataclass
class FallbackReport:
    primary: str
    fallback: tuple[str, ...]
    sessions: list[SessionFallback]

    @property
    def fell_back(self) -> list[SessionFallback]:
        return [s for s in self.sessions if s.fell_back]

    @property
    def fallback_usd(self) -> float:
        return sum(s.fallback_usd for s in self.sessions)

    @property
    def at_primary_usd(self) -> float:
        return sum(s.at_primary_usd for s in self.sessions)

    @property
    def premium_usd(self) -> float:
        return self.fallback_usd - self.at_primary_usd

    @property
    def observed_factor(self) -> float | None:
        """Fallback cost over the same tokens at the primary's rates, for the observed token mix."""
        return self.fallback_usd / self.at_primary_usd if self.at_primary_usd > 0 else None

    def to_dict(self) -> dict:
        return {"primary": self.primary, "fallback": list(self.fallback),
                "sessions": [s.to_dict() for s in self.sessions],
                "sessions_fell_back": len(self.fell_back),
                "sessions_stuck": sum(1 for s in self.sessions if s.stuck),
                "fallback_usd": round(self.fallback_usd, 6), "at_primary_usd": round(self.at_primary_usd, 6),
                "premium_usd": round(self.premium_usd, 6), "observed_factor": self.observed_factor}


def _check_models(primary: str, fallback) -> tuple[str, tuple[str, ...]]:
    if not isinstance(primary, str) or not primary:
        raise FallbackError("a primary model is required")
    fb = tuple(fallback or ())
    if not fb:
        raise FallbackError("at least one fallback model is required")
    if primary in fb:
        raise FallbackError(f"primary model {primary!r} is also listed as a fallback")
    return primary, fb


def detect_rows(log: str, rows, primary: str, fallback, prices: dict) -> SessionFallback:
    """Judge one session from its usage rows (tools.ledger.scan Claude rows)."""
    primary, fb = _check_models(primary, fallback)
    if primary not in prices["claude"]:
        raise pricing.PricingError(f"no price for primary model {primary!r} (add it to tools/ledger/pricing.json)")
    rows = list(rows)
    if not rows:
        raise FallbackError(f"{log}: no Claude assistant usage in it (not a Claude Code session log?)")
    s = SessionFallback(log=log)
    dated = sorted(((_when(r.get("ts")), i, r) for i, r in enumerate(rows) if _when(r.get("ts"))),
                   key=lambda t: (t[0], t[1]))
    s.undated_responses = len(rows) - len(dated)
    first_fb_at = None
    for when, _i, r in dated:
        if s.first_ts is None:
            s.first_ts = r["ts"]
        m = r.get("model")
        if m == primary:
            s.first_primary_ts = s.first_primary_ts or r["ts"]
            if first_fb_at is not None and when > first_fb_at:
                s.primary_after_fallback += 1
        elif m in fb and first_fb_at is None:
            first_fb_at, s.first_fallback_ts = when, r["ts"]
    for r in rows:
        m = r.get("model")
        if m == primary:
            s.primary_responses += 1
        elif m in fb:
            s.fallback_responses += 1
            if m not in s.fallback_models:
                s.fallback_models.append(m)
            s.fallback_usd += pricing.cost(r, prices)
            s.at_primary_usd += pricing.cost(dict(r, model=primary), prices)
        else:
            s.other_responses += 1
            if m not in s.other_models:
                s.other_models.append(m)
    if s.fell_back and s.undated_responses:
        raise FallbackError(f"{log}: {s.undated_responses} response(s) carry no readable timestamp, so "
                            "the fallback cannot be placed in time (when it started, whether it stuck)")
    return s


def detect(paths, primary: str, fallback, prices: dict | None = None) -> FallbackReport:
    """Judge each Claude Code session log in `paths` (one session per file)."""
    primary, fb = _check_models(primary, fallback)
    prices = prices if prices is not None else pricing.load_prices()
    sessions = []
    for p in paths:
        p = Path(p)
        if not p.is_file():
            raise FileNotFoundError(f"session log not found: {p}")
        sessions.append(detect_rows(str(p), scan.scan_claude(p).values(), primary, fb, prices))
    if not sessions:
        raise FallbackError("no session logs given")
    return FallbackReport(primary, fb, sessions)


def rate_ratios(prices: dict, primary: str, fallback: str) -> dict[str, float]:
    """Per token class: the fallback's rate over the primary's (cache_read is 2.5 for 4.8 vs 5.5)."""
    table = prices["claude"]
    for m in (primary, fallback):
        if m not in table:
            raise pricing.PricingError(f"no price for claude model {m!r} (add it to tools/ledger/pricing.json)")
    out = {}
    for k in TOKEN_CLASSES:
        a, b = table[primary][k], table[fallback][k]
        if a <= 0:
            raise pricing.PricingError(f"{primary!r} has a zero {k} rate; no ratio")
        out[k] = b / a
    return out


def worst_case_factor(prices: dict, primary: str, fallback) -> float:
    """The largest per-class ratio over every fallback model: the planning multiplier when the token
    mix is unknown (a cache-read-heavy agent approaches it)."""
    _p, fb = _check_models(primary, fallback)
    return max(max(rate_ratios(prices, primary, m).values()) for m in fb)


def _log_key(log: str) -> str:
    return hashlib.sha256(str(Path(log).resolve()).encode()).hexdigest()[:16]


def record(report: FallbackReport, *, workdir: Path | None = None, cyber_verified: str = "unknown",
           challenge_id: str | None = None) -> list[dict]:
    """Append one `model_fallback` ledger event per session that fell back and has not been recorded
    yet (keyed by the log's resolved path). Returns the new events. The event is an alert and a
    record for the replay (B-101); the spend itself is charged by tools.ledger feed."""
    from ctf import ledger as _ledger
    seen = {r.get("log_key") for r in _ledger.read(workdir) if r.get("event") == LEDGER_EVENT}
    out = []
    for s in report.fell_back:
        key = _log_key(s.log)
        if key in seen:
            continue
        fields = {"log": Path(s.log).name, "log_key": key, "from_model": report.primary,
                  "to_models": list(s.fallback_models), "first_fallback_ts": s.first_fallback_ts,
                  "minutes_to_fallback": s.minutes_to_fallback, "responses": s.fallback_responses,
                  "stuck": s.stuck, "fallback_only": s.fallback_only,
                  "premium_usd": round(s.premium_usd, 6), "cyber_verified": cyber_verified}
        if challenge_id:
            fields["challenge_id"] = challenge_id
        out.append(_ledger.append(LEDGER_EVENT, workdir=workdir, **fields))
        seen.add(key)
    return out
