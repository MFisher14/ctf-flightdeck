"""Cactus Needle: an optional on-device model for small picking jobs (M3, D15).

Needle is Cactus's small tool-calling model (cactus-compute, Apache-2.0). It runs on the CPU
in tens of milliseconds and needs no API key, so asking it costs nothing. flightdeck asks it
one kind of question: which of a few named options (techniques, the engines of an L1 pack)
a challenge's text points to, or none of them.

It is optional, and nothing in a run uses it unless the player asks:

- Install: `pip install "ctf-flightdeck[cactus]"` (cactus-compute, pinned). On first use,
  Cactus downloads its engine library and the Needle weights from its own servers; nothing of
  Cactus's ships with flightdeck.
- Telemetry: Cactus sends anonymous usage counts unless told not to. Before it loads Cactus,
  flightdeck sets CACTUS_TELEMETRY=0, DO_NOT_TRACK=1 and NEEDLE_TELEMETRY=0 (each only if the
  player has not set it), and refuses to go on if Cactus still says telemetry is on and the
  player did not turn it on themselves.
- Accuracy: measure it before trusting it (`flightdeck eval-local`). In the integrator's spike
  on invented challenge blurbs, Needle beat keyword rules only when it was given the same
  keywords as triggers, and then only by a little.

Challenge text is untrusted, and it is what Needle reads: a pick is only ever one of the
option names given (anything else counts as none), so the text can steer the choice among
them and nothing more.
"""

from __future__ import annotations

import importlib
import os
import re
import time
from collections.abc import MutableMapping, Sequence
from dataclasses import dataclass
from types import ModuleType

EXTRA = 'pip install "ctf-flightdeck[cactus]"'
TELEMETRY_OFF = (("CACTUS_TELEMETRY", "0"), ("DO_NOT_TRACK", "1"), ("NEEDLE_TELEMETRY", "0"))
NONE = "none_of_these"  # the option Needle picks when no other one fits
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_TEXT = 4000  # characters of challenge text Needle reads (it is small; the start says the most)


class NeedleError(Exception):
    """Needle cannot be used; the message says why and what to do."""


@dataclass(frozen=True)
class Option:
    name: str  # a function name for the model: lower-case letters, digits and _
    description: str  # what the option is, in a sentence
    triggers: tuple[str, ...] = ()  # words that point to it (matched by Cactus, case-insensitive)


@dataclass(frozen=True)
class Pick:
    option: str | None  # one of the options' names, or None: none fits
    confidence: float  # Cactus's own figure, 0 to 1
    seconds: float


def load(environ: MutableMapping[str, str] | None = None) -> ModuleType:
    """Import Cactus with its telemetry off. NeedleError when it is not installed, or when it
    would still send telemetry the player did not turn on."""
    env = os.environ if environ is None else environ
    chosen = {name for name, _ in TELEMETRY_OFF if name in env}
    for name, value in TELEMETRY_OFF:
        env.setdefault(name, value)
    try:
        cactus = importlib.import_module("cactus")
    except ImportError:
        raise NeedleError(f"Cactus is not installed: {EXTRA}") from None
    try:
        telemetry = importlib.import_module("cactus._telemetry")
    except ImportError:
        telemetry = None
    enabled = getattr(telemetry, "_enabled", None)
    if callable(enabled) and enabled() and not chosen:
        raise NeedleError(
            "Cactus says its telemetry is on although flightdeck turned it off (CACTUS_TELEMETRY=0, "
            "DO_NOT_TRACK=1); not using it. Set CACTUS_TELEMETRY yourself to decide"
        )
    return cactus


def tool_schemas(options: Sequence[Option]) -> list[dict]:
    """The options as Cactus tools, plus NONE."""
    names = [o.name for o in options]
    if not options:
        raise ValueError("Needle needs at least one option to pick from")
    for name in names:
        if not _NAME.fullmatch(name) or name == NONE:
            raise ValueError(f"option name {name!r} must be lower-case letters, digits and _ (and not {NONE})")
    if len(set(names)) != len(names):
        raise ValueError("option names must be unique")
    tools = []
    for option in options:
        tool: dict = {
            "name": option.name,
            "description": option.description,
            "parameters": {"type": "object", "properties": {}},
        }
        if option.triggers:
            tool["triggers"] = ["(" + "|".join(re.escape(t) for t in option.triggers) + ")"]
        tools.append(tool)
    tools.append({
        "name": NONE,
        "description": "None of the other tools fits this text.",
        "parameters": {"type": "object", "properties": {}},
    })
    return tools


class Picker:
    """Needle loaded once with a fixed set of options; pick() asks it about one text."""

    def __init__(self, options: Sequence[Option], *, cactus: ModuleType | None = None) -> None:
        self.options = tuple(options)
        self._names = {o.name for o in self.options}
        tools = tool_schemas(self.options)
        module = cactus if cactus is not None else load()
        try:
            self._agent = module.Cactus(tools=tools, auto_date=False, stateless=True)
        except Exception as exc:  # the engine or the weights could not load (first use needs the network)
            raise NeedleError(f"Cactus could not load Needle: {type(exc).__name__}: {exc}") from None

    def pick(self, text: str) -> Pick:
        begun = time.monotonic()
        try:
            answer = self._agent.complete(text[:MAX_TEXT])
        except Exception as exc:
            raise NeedleError(f"Needle failed: {type(exc).__name__}: {exc}") from None
        seconds = time.monotonic() - begun
        calls = answer.get("function_calls") if isinstance(answer, dict) else None
        name = None
        if isinstance(calls, list) and calls and isinstance(calls[0], dict):
            first = calls[0].get("name")
            name = first if isinstance(first, str) and first in self._names else None
        confidence = answer.get("confidence") if isinstance(answer, dict) else None
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            confidence = 0.0
        return Pick(name, float(confidence), seconds)

    def close(self) -> None:
        close = getattr(self._agent, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> Picker:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
