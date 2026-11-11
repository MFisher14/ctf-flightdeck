"""The hint judge: the light model's check on an "ignores the hint" alert (on when [light] names one).

Rules come first (HintDetector). With a judge, the Watch raises a rules HINT signal at once,
as the rules have it, and asks the judge in the background whether the lane is in fact using
the technique the description hints at. Nothing waits for the judge, and it never raises an
alert on its own: when it says the lane is using the technique, the Watch takes the alert
down (the lane's transcript says why) and keeps it down while that verdict stands; when it
says the lane is not, the alert stays.

The judge is the light model's judge_hint job (light.py), asked at most once per lane per
`judge_every_turns` turns, failed jobs included; in between, the last verdict (or failure)
stands. A job that fails (the model declined, the API failed or took longer than the [light]
timeout, or the answer was cut off, empty, or not "yes" or "no") gives no verdict: the rules'
answer stands, so the alert stays up and its reason says it is unconfirmed, and the deck shows
a warning once per kind of failure, naming the light model. Nothing moves a declined request
to another model: the player sees the refusal and decides.

What a job spent is reported to the deck as spend outside a turn (a SPEND event, why "the hint
judge (<engine> <model>)", the light model named): tokens and dollars on the lane's meter. The
cost is the API's figure, else the [light] price's, else unknown (None): the deck then treats
the lane as unpriced, and a dollar-capped lane asks the player before going on.

The description and the steps are untrusted: light.py fences and folds them for the model and
reads its answer strictly.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from ..agent import prompts
from ..core.deck import Deck
from ..core.driver import TurnReport
from ..core.model import Challenge, Lane
from ..light import ERROR, MAX_STEPS, NO, NO_ANSWER, OUTSIDE, REFUSED, TIMEOUT, Light
from .base import DetectConfig, quote, steps
from .hints import Technique

if TYPE_CHECKING:
    from ..config import Config

FENCE_OPEN = prompts.FENCE_OPEN
FENCE_CLOSE = prompts.FENCE_CLOSE

WHAT = {  # a failed job, for the player's warning
    REFUSED: "declined to judge",
    ERROR: "failed to judge",
    TIMEOUT: "took too long to judge",
    NO_ANSWER: "gave no answer about",
    OUTSIDE: "answered neither yes nor no about",
}


@dataclass(frozen=True)
class Judgement:
    """The judge's verdict on a rules HINT signal.

    `confirmed` is True when the judge agrees the lane ignores the hint (the alert stays), False
    when the lane is actually following the technique (the alert comes down), and None when
    there is no verdict (`reason` says why, `failure` names the light job's failure).
    """

    confirmed: bool | None
    answer: str  # "yes" or "no" as the judge answered; "" when there is no verdict
    reason: str  # why there is no verdict, when confirmed is None
    tokens: int = 0
    cost: float | None = 0.0  # dollars; None when the job's price is unknown
    cached: bool = False  # a recent verdict was reused without asking again
    failure: str = ""  # light.REFUSED, ERROR, TIMEOUT, NO_ANSWER or OUTSIDE when there is no verdict


class HintJudge:
    """The light model, judging whether a lane follows the technique its description hints at."""

    def __init__(self, light: Light, config: DetectConfig | None = None) -> None:
        self.light = light
        self.config = config or DetectConfig()
        self._last: dict[str, tuple[int, Judgement]] = {}  # lane id -> (turn asked, its verdict or failure)
        self._warned: set[str] = set()  # kinds of failure the player has been told about

    def recent(self, lane: Lane) -> Judgement | None:
        """The verdict (or failure) of a job made for `lane` within the last judge_every_turns
        turns, marked cached; None when it is time to ask again."""
        last = self._last.get(lane.id)
        if last is None or lane.turns - last[0] >= self.config.judge_every_turns:
            return None
        return replace(last[1], tokens=0, cost=0.0, cached=True)

    async def judge(self, lane: Lane, challenge: Challenge, technique: Technique, *, deck: Deck) -> Judgement:
        """Confirm or deny the rules HINT signal for `lane`. Rate-limited; reports spend to the
        deck; a failed job is a judgement with no verdict, said once per kind to the player."""
        cached = self.recent(lane)
        if cached is not None:
            return cached
        asked = lane.turns
        recent = steps(lane)[-MAX_STEPS:]
        answer = await self.light.judge_hint(technique, challenge.description, [a.text for a in recent],
                                             [a.output for a in recent])
        if answer.spent:
            deck.report(lane.id, TurnReport(
                turn=False, tokens=answer.tokens, cached_tokens=answer.cached_tokens, dollars=answer.cost,
                why=f"the hint judge ({self.light.label})", model=self.light.model or None,
            ))
        if answer.ok:
            judgement = Judgement(answer.choice == NO, answer.choice or "", "", tokens=answer.tokens, cost=answer.cost)
        else:
            reason = f"the light model ({self.light.label}) {WHAT.get(answer.failure, 'failed')} it: {quote(answer.why, 200)}"
            judgement = Judgement(None, "", reason, tokens=answer.tokens, cost=answer.cost, failure=answer.failure)
            self._warn(deck, lane, answer.failure, reason)
        self._last[lane.id] = (asked, judgement)
        return judgement

    def failed(self, lane: Lane, reason: str, *, turn: int | None = None, deck: Deck | None = None) -> Judgement:
        """Record that the judge gave no verdict for `lane` (its job broke in a way the light
        engine did not catch): for the next judge_every_turns turns, `recent` returns this
        failure instead of asking again. With `deck`, the player is told once."""
        judgement = Judgement(None, "", reason, failure=ERROR)
        self._last[lane.id] = (lane.turns if turn is None else turn, judgement)
        if deck is not None:
            self._warn(deck, lane, ERROR, reason)
        return judgement

    def forget(self, lane_id: str) -> None:
        self._last.pop(lane_id, None)

    async def aclose(self) -> None:
        await self.light.aclose()

    def _warn(self, deck: Deck, lane: Lane, failure: str, reason: str) -> None:
        if failure in self._warned:
            return
        self._warned.add(failure)
        deck.warn(
            f"{lane.id}: {reason}. The rules' answer stands: the hint alert stays up. Said once for this kind "
            "of failure; the light model is asked again later.",
            challenge=lane.challenge_id,
            data={"source": "light", "engine": self.light.engine, "model": self.light.model, "failure": failure,
                  "lane": lane.id},
        )


def from_config(config: Config, *, cactus=None) -> tuple[HintJudge | None, str]:
    """The hint judge for a run, and a line for the player about it ("" for none): None when
    [light] is absent or rules. A light model that cannot be made (a key not set, Cactus not
    installed) leaves the judge off and says why: the light role never stops a run."""
    from ..config import ConfigError, light_key
    from ..light import LightError, build

    light = config.light
    if light.engine == "rules":
        return None, ""
    try:
        engine = build(light, light_key(config), cactus=cactus)
    except (ConfigError, LightError) as exc:
        return None, f"the light model is off for this run, the rules answer alone: {exc}"
    note = (
        f"light model: {engine.label} judges each 'ignores the hint' alert (the alert shows at once; it comes down "
        "if the light model says the lane follows the hint; when it fails or refuses, the rules' answer stands)"
    )
    if light.engine == "anthropic" and light.price is None:
        note += (
            "; no [light] price in your config, so its calls are unpriced: a dollar-capped lane asks you once "
            "before it carries on without its cap"
        )
    return HintJudge(engine), note
