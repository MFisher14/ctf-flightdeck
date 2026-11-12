"""Anthropic's server-side refusal fallback: the models whose requests carry it, and the models
that answer for them.

A request to a model in SERVER_FALLBACK_MODELS carries the fallback (agent/anthropic_client.py):
a request its classifiers decline runs again, inside the same call, on the model Anthropic
recommends for that category. Anthropic's documentation (the claude-api skill's
shared/model-migration.md, its refusal section) says "fallback attempts bill at the fallback
model's rates", so a lane's meter prices that attempt as the model that ran it, from [prices].
FALLBACK_TARGETS are the models the documentation names as answering for each one; with [api]
provider = "anthropic", [prices] may price those that answer for a model of the ladder
(config.py), and `flightdeck init --provider anthropic` writes their prices (setup.py). From
the same file:

- Claude Sonnet 5.5: the fallback "retries `"cyber"` and `"frontier_llm"` declines on Claude
  Sonnet 5".
- Claude Opus 5.5: "read Claude Opus 5.5's permitted targets from `allowed_fallback_models` on
  its `/v1/models` entry, ... - expect Claude Opus 5 / claude-opus-4-8".
- Claude Opus 5: "cyber-category refusals go to Claude Opus 4.8".
- Claude Fable 5.1 and 5.2: "The permitted fallback targets are `claude-opus-4-8` and
  `claude-opus-5`".

Anthropic does not publish its per-category routing. A model it answers with that is not
listed here can have no price, so a lane it answers for reads its dollars as not fully known,
as for any spend with no price (P7). Claude Haiku 5.5 has no server-side fallback.

Nothing here imports the Anthropic SDK: the config reads it.
"""

from __future__ import annotations

FALLBACK_BETA = "server-side-fallback-2026-07-01"  # the beta that takes fallbacks="default"

FALLBACK_TARGETS: dict[str, tuple[str, ...]] = {
    "claude-sonnet-5-5": ("claude-sonnet-5",),
    "claude-opus-5-5": ("claude-opus-5", "claude-opus-4-8"),
    "claude-opus-5": ("claude-opus-4-8",),
    "claude-fable-5-1": ("claude-opus-4-8", "claude-opus-5"),
    "claude-fable-5-2": ("claude-opus-4-8", "claude-opus-5"),
}
"""Each model with the server-side fallback, and the models that answer for it (see above)."""

SERVER_FALLBACK_MODELS = frozenset(FALLBACK_TARGETS)
"""The models whose requests carry the server-side refusal fallback by default (Anthropic's
documentation). Claude Haiku 5.5 is not one: it has none, and a fallbacks list is a 400 there."""


def answering(models: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """The models the refusal fallback may answer with for `models`, each once, in order."""
    return tuple(dict.fromkeys(target for model in models for target in FALLBACK_TARGETS.get(model, ())))
