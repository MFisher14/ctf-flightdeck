"""Rules-first detectors for the course alerts (effort, ignores-the-hint, wrong direction,
loop, stall), with the hint lexicon behind the "ignores the hint" detector.

Detectors observe a lane and its challenge and signal when a course alert holds now; they
never change a lane. The Watch (added alongside) runs them after each turn and raises or
clears their alerts through the deck.

Everything a detector reads from a challenge or a lane is untrusted text (AGENTS.md rule
5): it is matched against flightdeck's own word lists and rules only, never followed, and
anything quoted back is folded to one short line.
"""

from __future__ import annotations

from .base import DetectConfig, Detector, Signal, quote
from .detectors import (
    DirectionDetector,
    EffortDetector,
    HintDetector,
    LoopDetector,
    StallDetector,
    default_detectors,
)
from .hints import (
    Hinted,
    Lexicon,
    LexiconError,
    Technique,
    lexicon,
    load_lexicon,
    named_techniques,
    top_technique,
)
from .judge import HintJudge, Judgement
from .watch import Watch

__all__ = [
    "DetectConfig",
    "Detector",
    "Signal",
    "quote",
    "EffortDetector",
    "HintDetector",
    "DirectionDetector",
    "LoopDetector",
    "StallDetector",
    "default_detectors",
    "Watch",
    "HintJudge",
    "Judgement",
    "Lexicon",
    "LexiconError",
    "Technique",
    "Hinted",
    "lexicon",
    "load_lexicon",
    "named_techniques",
    "top_technique",
]
