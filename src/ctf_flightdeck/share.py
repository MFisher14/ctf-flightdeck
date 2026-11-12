"""`flightdeck share RUN_DIR`: a run's flight card, to paste where the player chooses.

A flight card says what was run (flightdeck's version, where lanes ran, the models) and how
it went (solves by category, time, spend, how often the player stepped in, and the mode), so
that cards from many players show which setup does what. It is built to be posted in public,
so it holds no flag, no challenge name or id, no challenge text, no event name, no path and no
address: categories are the console's short codes or "other", and the setup comes from
RUN_DIR/setup.json, which names models and settings only. Model ids are the player's own
config; every string still goes through text.untrusted, since a lane on the host can write in
the run folder.

Nothing is sent anywhere: the card is printed (D22).

The mode is one of three words, worked out from the run's interventions (docs/LEADERBOARD.md):
hands-on (the player steered a lane), approve-only (the player only approved or declined) or
hands-off (nobody touched a lane).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from statistics import median

from . import fmt
from .platform.manual import CATEGORY_CODES, category_code
from .postflight import STEP_NAMES, VERDICTS, Flight, analyse
from .runrecord import LANE, RunRecord
from .text import untrusted

HANDS_ON, APPROVE_ONLY, HANDS_OFF = "hands-on", "approve-only", "hands-off"
MODES = {
    HANDS_ON: "you steered lanes during the run",
    APPROVE_ONLY: "you only approved or declined; no steering",
    HANDS_OFF: "nobody touched a lane",
}
NOT_STEERING = VERDICTS | {"handback"}  # handing a lane back ends a take-over, which is counted
SAID = {"approve": "approved", "decline": "declined"}
OTHER = "other"
TEXT_LIMIT = 80  # a model id or a setting, cut to this
TITLE = "flightdeck flight card"
PRACTICE = "the practice set"


def _text(value: object) -> str:
    """A string from the run folder, safe to print on one line and cut short."""
    text = untrusted(value if isinstance(value, str) else "", one_line=True).strip()
    return text if len(text) <= TEXT_LIMIT else text[: TEXT_LIMIT - 1] + "…"


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _strings(value: object) -> list[str]:
    return [text for item in value if (text := _text(item))] if isinstance(value, list) else []


def category(name: str) -> str:
    """A challenge's category as a card shows it: one of the console's codes, else "other"
    (a board's own category name is the board's text, and stays out of a card)."""
    code = category_code(name)
    return code if code in set(CATEGORY_CODES.values()) else OTHER


def steering(flight: Flight) -> Counter[str]:
    """The player's steering interventions that took effect, by name."""
    return Counter(
        STEP_NAMES.get(step.name, step.name)
        for step in flight.steps
        if step.ok is not False and step.name not in NOT_STEERING
    )


def verdicts(flight: Flight) -> Counter[str]:
    """The player's approvals and declines that took effect, by name."""
    return Counter(step.name for step in flight.steps if step.ok is not False and step.name in VERDICTS)


def mode(flight: Flight) -> str:
    if steering(flight):
        return HANDS_ON
    return APPROVE_ONLY if verdicts(flight) else HANDS_OFF


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _money(dollars: float, unpriced: int) -> str:
    return f"at least ${fmt.dollars(dollars)} (some spend had no price)" if unpriced else f"${fmt.dollars(dollars)}"


def _setup_lines(setup: Mapping[str, object] | None) -> list[str]:
    if setup is None:
        return ["setup: not recorded (a run from before flightdeck 0.3.0)"]
    lanes = _text(setup.get("lanes")) or "flightdeck"
    who = "flightdeck's own lanes" if lanes == "flightdeck" else f"{lanes} lanes (a coding-agent CLI)"
    api = _text(setup.get("api"))
    parts = [_text(setup.get("runtime")) or "unknown runtime"]
    if (most := _int(setup.get("max_lanes"))) is not None:
        parts.append(f"{_plural(most, 'lane')} at once")
    parts.append(f"submit {_text(setup.get('submit')) or 'unknown'}")
    out = ["setup: " + ", ".join(parts), f"lanes: {who}" + (f" on {api}" if api else "")]
    ladder = _strings(setup.get("ladder"))
    out.append("ladder: " + (" > ".join(ladder) if ladder else "not recorded"))
    if fallback := _text(setup.get("fallback")):
        out.append(f"fallback: {fallback}")
    if fast := _strings(setup.get("fast")):
        out.append("fast mode: " + ", ".join(fast))
    lights = setup.get("light") if isinstance(setup.get("light"), list) else []
    shown = []
    for light in lights:
        if not isinstance(light, Mapping):
            continue
        name = _text(light.get("model")) or _text(light.get("engine"))
        jobs = ", ".join(_strings(light.get("jobs")))
        where = _text(light.get("api"))
        shown.append(name + (f" on {where}" if where else "") + (f" ({jobs})" if jobs else ""))
    out.append("light model: " + ("; ".join(shown) if shown else "none"))
    engines = _int(setup.get("l1_engines"))
    out.append("L1 pack: " + (_plural(engines, "engine") if engines else "none"))
    caps = []
    if (tokens := _int(setup.get("token_cap"))) is not None:
        caps.append(f"{fmt.tokens(tokens)} tokens")
    cap = setup.get("dollar_cap")
    if isinstance(cap, (int, float)) and not isinstance(cap, bool) and cap > 0:
        caps.append(f"${fmt.dollars(float(cap))}")
    out.append("lane caps: " + (" or ".join(caps) if caps else "none"))
    if setup.get("team") is True:
        out.append("team mode: on")
    return out


def _board_line(flight: Flight, setup: Mapping[str, object] | None) -> str:
    count = _plural(len(flight.challenges), "challenge")
    kind = _text(setup.get("board")) if setup is not None else ""
    if kind == "practice":
        return f"board: {PRACTICE} ({count})"
    if kind == "ctfd":
        return f"board: a CTFd event ({count})"
    return f"board: a folder board ({count})"


def _by_category(flight: Flight) -> str:
    total: Counter[str] = Counter()
    solved: Counter[str] = Counter()
    for cid, facts in flight.challenges.items():
        code = category(facts.category)
        total[code] += 1
        if cid in flight.solves:
            solved[code] += 1
    order = sorted(total, key=lambda code: (code == OTHER, code))
    return ", ".join(f"{code} {solved[code]}/{total[code]}" for code in order) or "no challenges"


def _lane_solves(flight: Flight) -> list[tuple[str, float | None, int]]:
    """(the model that solved, seconds from the lane's start, the lane's turns) per lane solve."""
    out = []
    for solve in flight.solves.values():
        lane = flight.lanes.get(solve.who) if solve.by == LANE else None
        if lane is None:
            continue
        took = solve.at - lane.started_at if solve.at is not None and lane.started_at is not None else None
        out.append((lane.models[-1] if lane.models else "", took if took is None or took >= 0 else None, lane.turns))
    return out


def _model_lines(flight: Flight, lane_solves: Sequence[tuple[str, float | None, int]]) -> list[str]:
    wins = Counter(model for model, _, _ in lane_solves)
    out = []
    for spend in flight.models:
        name = _text(spend.model) or "unknown model"
        out.append(
            f"  {name}: {_plural(spend.turns, 'turn')}, {fmt.tokens(spend.tokens)} tokens, "
            f"{_money(spend.dollars, spend.unpriced)}, {_plural(wins.get(spend.model, 0), 'lane solve')}"
        )
    return out


def card(record: RunRecord, setup: Mapping[str, object] | None, *, version: str = "", label: str = "") -> str:
    """The flight card of a run, as text. `setup` is what read_run_setup gave (None: nothing
    recorded); `version` the flightdeck that played it; `label` the player's own name for it."""
    flight = analyse(record)
    solved = len(flight.solves)
    by = Counter(solve.by for solve in flight.solves.values())
    lane_solves = _lane_solves(flight)
    dollars, unpriced = flight.dollars
    steer, said = steering(flight), verdicts(flight)
    which = mode(flight)
    out = [TITLE]
    if label := _text(label):
        out.append(f"name: {label}")
    out.append(f"flightdeck: {_text(version) or 'unknown version'}")
    out.append(f"date: {_text(record.started)[:10] or 'unknown'}")
    out.append(_board_line(flight, setup))
    out += _setup_lines(setup)
    out.append("")
    credit = ", ".join(f"{name} {by[key]}" for key, name in ((LANE, "lanes"), ("l1", "L1")) if by[key])
    others = solved - by[LANE] - by["l1"]
    if others:
        credit += (", " if credit else "") + f"outside the lanes {others}"
    out.append(f"solved: {solved} of {len(flight.challenges)}" + (f" ({credit})" if credit else ""))
    out.append(f"by category: {_by_category(flight)}")
    out.append(f"time: {fmt.duration(flight.duration)} for the run")
    times = [took for _, took, _ in lane_solves if took is not None]
    if times:
        turns = [n for _, _, n in lane_solves]
        out.append(f"a lane solve took: {fmt.duration(median(times))} and {round(median(turns))} turns (median)")
    cached = f", {round(100 * flight.cached / flight.tokens)}% cached" if flight.tokens else ""
    out.append(f"spend: {fmt.tokens(flight.tokens)} tokens{cached}, {_money(dollars, unpriced)}")
    if by[LANE] and not unpriced:
        out.append(f"cost per lane solve: ${fmt.dollars(dollars / by[LANE])}")
    if flight.models:
        out.append("by model:")
        out += _model_lines(flight, lane_solves)
    out.append("")
    out.append(f"lanes started: {len(flight.lanes)}, {_plural(flight.turns, 'turn')}")
    out.append("you approved or declined: " + (", ".join(f"{said[name]} {SAID[name]}" for name in sorted(said)) or "nothing"))
    out.append("you steered: " + (", ".join(f"{steer[name]} {name}" for name in sorted(steer)) or "nothing"))
    out.append(f"mode: {which} ({MODES[which]})")
    return "\n".join(out) + "\n"
