"""Fast mode on the Anthropic Messages API: which models have it, and at what price.

Fast mode runs the same model at up to 2.5x the output speed, at a premium price. A player
opts in per ladder model (`[api] fast = ["claude-opus-5-5"]`), and only for a model listed
here; any other is refused with the reason. The facts come from Anthropic's API documentation
(SKILL.md, "Fast Mode"; shared/model-migration.md and shared/platform-availability.md), not
from memory:

- Claude Opus 5.5: `speed: "fast"` on a plain Messages request, no beta flag, $8 / $40 per
  million input / output tokens (2x the standard price).
- Claude Fable 5.2 and Claude Mythos 5.2: the same, on the Claude API, at $16 / $80.
- Claude Opus 5 and Claude Opus 4.8: a research preview, on the Claude API only, that also
  needs the beta flag `fast-mode-2026-02-01`, at $10 / $50. Opus 5 needs access from
  Anthropic (an account manager, or the waitlist). Fast mode on Opus 4.8 is removed on
  2026-11-30; after that `speed: "fast"` on it returns an error.

Fast mode has its own rate limit, separate from the standard one. On a 429 the documentation gives
two choices, waiting for retry-after or dropping `speed` to go on at standard speed; the
Anthropic client drops it, says so, and stays at standard speed for the rest of that lane's
context, because switching speed invalidates the prompt cache.

A fast call is priced at the fast rate. The skill gives fast mode's input and output prices
only, so a fast call's prompt tokens read from the cache, and those it writes to the cache,
are priced at the fast input rate. An attempt the refusal fallback ran on another model is
priced as that model: at its fast rate here when the API says that attempt ran fast, else
from the config (agent/anthropic_client.py fast_priced: the API says the speed of a call's
last attempt only).

Nothing here imports the Anthropic SDK: the config checks `[api] fast` with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from ..pricing import Price

FAST_BETA = "fast-mode-2026-02-01"  # the beta flag the research-preview models need


@dataclass(frozen=True)
class FastMode:
    """One model's fast mode, as Anthropic's documentation lists it."""

    model: str
    price: Price  # dollars per million tokens at fast speed (cache reads and writes: the input rate)
    beta: bool = False  # a research preview: the request needs FAST_BETA
    access: bool = False  # Anthropic must give the account access first
    until: date | None = None  # fast mode on this model is removed on this day


FAST_MODES: dict[str, FastMode] = {
    mode.model: mode
    for mode in (
        FastMode("claude-opus-5-5", Price(input=8.0, output=40.0)),
        FastMode("claude-fable-5-2", Price(input=16.0, output=80.0)),
        FastMode("claude-mythos-5-2", Price(input=16.0, output=80.0)),
        FastMode("claude-opus-5", Price(input=10.0, output=50.0), beta=True, access=True),
        FastMode("claude-opus-4-8", Price(input=10.0, output=50.0), beta=True, until=date(2026, 11, 30)),
    )
}


def today() -> date:
    """Today's date (a function, so a test can move the calendar)."""
    return date.today()


def fast_problem(model: str, on: date | None = None) -> str | None:
    """Why `model` cannot run in fast mode (on day `on`, default today), or None when it can."""
    mode = FAST_MODES.get(model)
    if mode is None:
        return f"{model} has no fast mode; fast mode is for {listed()}"
    when = on or today()
    if mode.until is not None and when >= mode.until:
        return f"fast mode on {model} was removed on {mode.until.isoformat()}; fast mode is for {listed(when)}"
    return None


def fast_note(models: tuple[str, ...] | list[str]) -> str:
    """What a run says before it starts about the models it calls in fast mode."""
    parts = []
    for model in models:
        mode = FAST_MODES[model]
        part = f"{model} (${mode.price.input:g} / ${mode.price.output:g} per million tokens"
        if mode.access:
            part += "; your account needs access from Anthropic"
        if mode.until is not None:
            part += f"; until {mode.until.isoformat()}"
        parts.append(part + ")")
    return (f"fast mode: {', '.join(parts)}. It has its own rate limit: on a 429 the lane goes on at standard "
            "speed for the rest of its session, and says so")


def listed(on: date | None = None) -> str:
    """The models with fast mode on day `on` (default today), as a phrase."""
    when = on or today()
    names = []
    for mode in FAST_MODES.values():
        if mode.until is not None and when >= mode.until:
            continue
        extra = []
        if mode.beta:
            extra.append("research preview")
        if mode.until is not None:
            extra.append(f"until {mode.until.isoformat()}")
        names.append(mode.model + (f" ({', '.join(extra)})" if extra else ""))
    return ", ".join(names)
