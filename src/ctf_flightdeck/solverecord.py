"""Solve records: for one challenge a run solved, who did what, from the run's own log.

Some events ask a team to show how it solved a challenge: the lanes' trajectories, what the
people did, who let the flag go. `record(...)` writes that for one solve as Markdown, from a
run folder (runrecord.load_run) and nothing else:

- the solve: the challenge, when it was solved, the flag, who it is credited to by the rule
  every report uses (runrecord.Credit), and how the flag went to the platform: the player
  approved it, it went on its own under submit auto, or the player submitted it by hand and
  said it was accepted (who_sent());
- the label the team declared to the event (the profile's rules.declared_label, as the run
  recorded it in setup.json), with the words that flightdeck did not check it;
- who did what on this challenge, counted: the lanes and their turns, the no-model solvers'
  runs, the player's interventions and autopilot's;
- every flag sent for the challenge, right or wrong, with who let each go;
- every intervention on the challenge and its lanes, the player's and autopilot's apart, each
  with its time, its own words (a hint's text, a redirect's) and what came of it;
- every lane that worked the challenge, and each one's whole transcript: every entry in
  order, each turn with all of its tool calls and what the transcript kept of their output,
  flightdeck's notes, the alerts, the approvals, and the files changed with their diffs. The
  lane the solve is credited to comes first.

Nothing is picked, summarised or reworded, and no model is asked for anything: a record is
evidence, and it says only what the log says. Where the log does not say something (a run
folder from before submits recorded the approval; a lane with no transcript), the record says
that, never a guess.

A record is not for posting. It holds the challenge's own text, commands, outputs and the
flag, which are the player's to hand to the event's organisers and nobody else's; the flight
card (share.py) is the thing made to be public, and it holds none of them. Nothing is sent
anywhere: `flightdeck records` writes files in the run folder.

Credentials: the run is read with the value of anything shaped like a credential taken out
(postflight.analyse does that for the log and each transcript entry; the tool calls of a turn
and the file diffs are cleaned here the same way), so a run folder written before transcripts
were cleaned as they were written does not put a key in a record. Flags stay.

Untrusted text: everything from the run is challenge text, model output or a lane's files.
One-line values are plain only when nothing in them means anything in Markdown, else a code
span (writeup.inline, writeup.code); anything longer is a fenced block whose fence no line
inside can close (writeup.fenced). So nothing from the run is ever raw HTML, a link or a
heading in a record.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence

from . import credentials, fmt
from .postflight import AUTOPILOT, STEP_NAMES, Flight, LaneFacts, Step, analyse
from .preflight import is_label
from .runrecord import L1, LANE, ActionLine, LaneRecord, RunRecord, run_time
from .runrecord import Solve as Credited
from .runrecord import solves as first_solves
from .writeup import code, fenced, inline

__all__ = ["NOT_SOLVED", "SolveRecordError", "record", "solved", "who_sent"]

NOT_FOR_POSTING = (
    "It holds the challenge's own text, the commands and outputs of the lanes and the flag: it is for the event's "
    "organisers, and not for posting."
)
NO_MODEL_WROTE_IT = "No model wrote, picked or reworded any of it."
LABEL_NOT_CHECKED = "the team's word to the event; flightdeck does not check it"
NOT_SOLVED = "has no accepted flag in this run"

APPROVED = "you approved it, and flightdeck then sent it to be checked"
ON_ITS_OWN = "nobody approved it: flightdeck sent it to be checked as soon as the lane claimed it (submit auto)"
BY_HAND = "you submitted it on the platform yourself and told flightdeck how it went"
NOT_IN_THE_LOG = (
    "the log does not say whether you approved it (this run was played with a flightdeck from before submits recorded "
    "that); every approval you gave is among your interventions below"
)

_WHO = {"lane": "the lane's model", "player": "you", "flightdeck": "flightdeck", AUTOPILOT: "autopilot"}
_OWN_FIELDS = ("intervention", "lane", "challenge", "by")  # of an intervention's data: said in its line already


class SolveRecordError(Exception):
    """The run has no such solve to record; the message says why."""


def who_sent(data: Mapping[str, object]) -> str:
    """How a flag went to the platform, in words, from its submit event's data: the player's
    yes (`approved` true), on its own under submit auto (`approved` false), or by the player's
    own hand (`by` "player": no flightdeck submit at all). A log that does not say is said
    not to say."""
    if data.get("by") == "player":
        return BY_HAND
    approved = data.get("approved")
    if approved is True:
        return APPROVED
    if approved is False:
        return ON_ITS_OWN
    return NOT_IN_THE_LOG


def solved(run: RunRecord) -> list[str]:
    """The challenges the run solved with an accepted flag, in the order they were solved:
    those a record can be written for (a teammate's solve, or one the platform lists, came
    with no flag of this run). The first accepted flag of each, credited by the rule every
    report uses (runrecord.Credit), as writeups take them."""
    return list(first_solves(run.events, flags_only=True))


def record(
    run: RunRecord, challenge_id: str, *, setup: Mapping[str, object] | None = None, flight: Flight | None = None,
) -> str:
    """The solve record of one challenge, as Markdown. `setup` is what the run recorded about
    itself (runrecord.read_run_setup; None: nothing); `flight` the run already analysed
    (postflight.analyse), to write several records without reading the run again.
    SolveRecordError when the run has no accepted flag for the challenge."""
    flight = flight if flight is not None else analyse(run)
    credit = first_solves(flight.record.events, flags_only=True).get(challenge_id)
    if credit is None:
        known = challenge_id in flight.challenges
        why = NOT_SOLVED if known else "is not in this run"
        raise SolveRecordError(f"challenge {_fold(challenge_id)!r} {why}: there is no solve to record")
    return _Writer(flight, credit, setup).markdown()


# ---------------------------------------------------------------------- the writer


def _fold(text: object) -> str:
    from .text import untrusted

    return untrusted(text if isinstance(text, str) else "", one_line=True)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _clock(at: float | None) -> str:
    return fmt.clock(at) if at is not None else "T+?"


class _Writer:
    def __init__(self, flight: Flight, credit: Credited, setup: Mapping[str, object] | None) -> None:
        self.flight = flight
        self.run = flight.record  # read without its credentials
        self.credit = credit
        self.cid = credit.challenge
        self.setup = setup
        self.submit = self.run.events[credit.index]
        keep = tuple(dict.fromkeys(flag for event in self.run.events for flag in credentials.named_flags(event.data)))
        self.clean = lambda text: credentials.redact(text, keep=keep)
        # the lanes that worked this challenge, the credited one first, the rest as they started
        on = [facts for facts in flight.lanes.values() if facts.challenge == self.cid]
        first = credit.lane if credit.lane is not None else (credit.who if credit.by == LANE else None)
        self.lanes = sorted(on, key=lambda facts: facts.id != first)
        self.first = first if any(facts.id == first for facts in on) else None
        mine = {facts.id for facts in on}

        def here(step: Step) -> bool:
            return step.challenge == self.cid or (step.lane is not None and step.lane in mine)

        self.steps = [step for step in flight.steps if here(step)]
        self.by_rule = [step for step in flight.by_rule if here(step)]
        # autopilot flew some of the run: the log says it was engaged, or holds an intervention it made (on any
        # challenge: a log that lost its engage line still shows that much)
        self.engaged = bool(flight.pilot or flight.by_rule)
        self.l1_runs = [event for event in self.run.events if event.kind == L1 and event.challenge == self.cid]
        self.submits = [event for event in self.run.events if event.kind == "submit" and event.challenge == self.cid]

    # ------------------------------------------------------------------ the whole

    def markdown(self) -> str:
        info = self.flight.challenges.get(self.cid)
        name = (info.name if info is not None else "") or self.cid
        out = [f"# Solve record: {inline(name)}", ""]
        out += [
            "flightdeck wrote this record from one run's own log and lane transcripts: who worked this challenge, what each "
            "lane's model did turn by turn, every time the operator stepped in, and how each flag went to the platform. "
            f"{NO_MODEL_WROTE_IT} {NOT_FOR_POSTING}",
            "",
        ]
        out += self._solve(name)
        out += self._counts()
        out += self._flags()
        out += self._interventions("Your interventions", self.steps, "You made no intervention on this challenge or its lanes.")
        if self.engaged:
            out += self._interventions("Autopilot's interventions, by rule", self.by_rule,
                                       "Autopilot made no intervention on this challenge or its lanes.")
        out += self._l1()
        out += self._lane_list()
        for facts in self.lanes:
            out += self._transcript(facts)
        if self.run.problems:
            out += ["## What could not be read", "",
                    "These lines of the run folder were skipped, so the record may lack what they held:", ""]
            out += [f"- {inline(problem)}" for problem in self.run.problems]
            out.append("")
        return "\n".join(out).rstrip("\n") + "\n"

    # ------------------------------------------------------------------ the solve

    def _solve(self, name: str) -> list[str]:
        info = self.flight.challenges.get(self.cid)
        start = next((event for event in self.run.events if event.kind == "run-start"), None)
        version = start.data.get("version") if start is not None else None
        out = ["## The solve", ""]
        facts = [f"id {code(self.cid)}"]
        if info is not None and info.category:
            facts.append(f"category {inline(info.category)}")
        if info is not None and info.points is not None:
            facts.append(_plural(info.points, "point"))
        out.append(f"- Challenge: {inline(name)} ({', '.join(facts)})")
        if self.flight.event:
            out.append(f"- Event: {inline(self.flight.event)}")
        played = f"flightdeck {inline(version)}" if isinstance(version, str) and version else "a flightdeck that did not record its version"
        out.append(f"- Run: started {inline(self.run.started or 'at a time the log does not give')}, played with {played}")
        out.append(f"- Setup: {self._setup()}")
        out.append(f"- Declared label: {self._label()}")
        when = self.submit.wall and f" ({inline(self.submit.wall)})"
        out.append(f"- Solved: {_clock(run_time(self.submit.at))} into the run{when}")
        out.append(f"- Flag: {code(self.credit.flag or '')}")
        out.append(f"- Credited to: {self._credited()}")
        out.append(f"- How the flag went to the platform: {who_sent(self.submit.data)}")
        out.append("- Autopilot: " + ("was engaged at some point of this run; what it did on this challenge is listed below"
                                      if self.engaged else "was not engaged in this run"))
        return [*out, ""]

    def _setup(self) -> str:
        setup = self.setup
        if setup is None:
            return "not recorded (the run folder has no setup.json)"

        def text(key: str) -> str:
            value = setup.get(key)
            return _fold(value).strip() if isinstance(value, str) else ""

        lanes = text("lanes") or "flightdeck"
        who = "flightdeck's own lanes" if lanes == "flightdeck" else f"{inline(lanes)} lanes (a coding-agent CLI)"
        ladder = setup.get("ladder")
        models = [inline(item) for item in ladder if isinstance(item, str) and item] if isinstance(ladder, list) else []
        parts = [who, f"models {' then '.join(models)}" if models else "models not recorded"]
        parts.append(f"lanes ran in {inline(text('runtime'))}" if text("runtime") else "runtime not recorded")
        parts.append(f"submit policy {inline(text('submit'))} when the run started" if text("submit") else "submit policy not recorded")
        return "; ".join(parts)

    def _label(self) -> str:
        value = self.setup.get("label") if self.setup is not None else None
        if self.setup is None:
            return "not recorded (the run folder has no setup.json)"
        if value is None or value == "":
            return "none (the run's event profile declared none, or the run had no event profile)"
        if not is_label(value):
            return "not shown (what the run folder holds for it is not a label)"
        return f"{value} ({LABEL_NOT_CHECKED})"

    def _credited(self) -> str:
        credit = self.credit
        if credit.by == L1:
            through = f", and went to the platform through lane {inline(credit.lane)}" if credit.lane else ""
            return f"the no-model solver {inline(credit.who)} (L1), which reported the flag before it was accepted{through}"
        if credit.by == LANE:
            facts = self.flight.lanes.get(credit.who)
            models = " then ".join(inline(model) for model in facts.models) if facts is not None and facts.models else ""
            return f"lane {inline(credit.who)}" + (f", on the model {models}" if models else "")
        return "you: no lane submitted this flag"

    # ------------------------------------------------------------------ who did what

    def _counts(self) -> list[str]:
        turns = sum(facts.turns for facts in self.lanes)
        out = ["## Who did what on this challenge", ""]
        out.append(f"- Lanes (AI agents): {_plural(len(self.lanes), 'lane')}, {_plural(turns, 'turn')} in all "
                   "(a turn is one reply of the lane's model, with the tool calls it made)")
        out.append(f"- No-model solvers (L1): {_plural(len(self.l1_runs), 'run')}")
        out.append(f"- You: {self._tally(self.steps)}")
        out.append(f"- Autopilot, by rule: {self._tally(self.by_rule)}")
        return [*out, ""]

    @staticmethod
    def _tally(steps: Sequence[Step]) -> str:
        took = Counter(STEP_NAMES.get(step.name, step.name) for step in steps if step.ok is not False)
        refused = sum(1 for step in steps if step.ok is False)
        if not steps:
            return "no interventions"
        said = ", ".join(f"{count} {inline(name)}" for name, count in sorted(took.items())) or "none that took effect"
        return f"{_plural(len(steps), 'intervention')}: {said}" + (f"; {refused} refused" if refused else "")

    # ------------------------------------------------------------------ the flags

    def _flags(self) -> list[str]:
        out = ["## Flags sent for this challenge", ""]
        if not self.submits:
            return [*out, "None.", ""]
        out.append("Every flag that got a verdict, in order, right or wrong:")
        out.append("")
        for event in self.submits:
            flag = event.data.get("flag")
            ok = event.data.get("correct")
            verdict = "accepted" if ok is True else "wrong" if ok is False else "no verdict"
            judge = "by your word" if event.data.get("by") == "player" else "by the platform"
            lane = f"lane {inline(event.lane)}" if event.lane else "no lane"
            out.append(f"- {_clock(run_time(event.at))} · {lane} · {code(flag if isinstance(flag, str) else '')} · "
                       f"{verdict} {judge} · {who_sent(event.data)}")
        return [*out, ""]

    # ------------------------------------------------------------------ interventions

    def _interventions(self, title: str, steps: Sequence[Step], none: str) -> list[str]:
        out = [f"## {title}", ""]
        if not steps:
            return [*out, none, ""]
        for step in steps:
            event = self.run.events[step.index]
            name = STEP_NAMES.get(step.name, step.name)
            on = f"lane {inline(step.lane)}" if step.lane else "the challenge"
            if step.ok is None:
                came = "no outcome in the log"
            elif step.ok:
                came = "took effect" + (f": {inline(step.message)}" if step.message else "")
            else:
                came = "refused" + (f": {inline(step.message)}" if step.message else "")
            wall = f" ({inline(event.wall)})" if event.wall else ""
            answers = f" · answered the approval for {inline(step.answers)}" if step.answers else ""
            out.append(f"- {_clock(step.at)}{wall} · {inline(name)} · {on}{answers} · {came}")
            said = [f"{key}: {self._value(value)}" for key, value in step.data.items() if key not in _OWN_FIELDS and value not in (None, "")]
            if said:
                out += ["", fenced("\n".join(said)), ""]
        return [*out, ""]

    @staticmethod
    def _value(value: object) -> str:
        if isinstance(value, bool):
            return "yes" if value else "no"
        return value if isinstance(value, str) else str(value)

    # ------------------------------------------------------------------ L1

    def _l1(self) -> list[str]:
        if not self.l1_runs:
            return []
        out = ["## No-model solvers (L1) on this challenge", "",
               "An L1 engine is a program of the player's own that runs without a model. What each run recorded:", ""]
        for event in self.l1_runs:
            data = event.data
            flags = [flag for flag in data.get("flags", []) if isinstance(flag, str) and flag] if isinstance(data.get("flags"), list) else []
            parts = [_clock(run_time(event.at)), f"engine {inline(_text(data.get('engine')) or '?')}",
                     f"status {inline(_text(data.get('status')) or '?')}"]
            if event.lane:
                parts.append(f"on lane {inline(event.lane)}")
            parts.append("flags reported: " + (", ".join(code(flag) for flag in flags) if flags else "none"))
            if _text(data.get("notes")):
                parts.append(f"notes: {inline(_text(data.get('notes')))}")
            out.append("- " + " · ".join(parts))
        return [*out, ""]

    # ------------------------------------------------------------------ the lanes

    def _lane_list(self) -> list[str]:
        out = ["## Lanes that worked this challenge", ""]
        if not self.lanes:
            return [*out, "None: no lane worked it in this run.", ""]
        for facts in self.lanes:
            parts = [f"lane {inline(facts.id)}"]
            parts.append("model " + (" then ".join(inline(model) for model in facts.models) if facts.models else "not recorded"))
            parts.append(f"started {_clock(facts.started_at)}")
            parts.append(f"ended {_clock(facts.ended_at)}" if facts.ended_at is not None else "open when the log ends")
            if facts.state:
                parts.append(f"state {inline(facts.state)}")
            parts.append(_plural(facts.turns, "turn"))
            parts.append(f"{facts.tokens:,} tokens")
            if facts.parent:
                parts.append(f"forked from lane {inline(facts.parent)}")
            if facts.id == self.first:
                parts.append("the lane the accepted flag was sent on")
            out.append("- " + " · ".join(parts))
        return [*out, ""]

    def _transcript(self, facts: LaneFacts) -> list[str]:
        head = facts.record
        credited = " (the lane the accepted flag was sent on)" if facts.id == self.first else ""
        out = [f"## Transcript of lane {inline(facts.id)}{credited}", ""]
        if head is None:
            return [*out, f"This lane has no transcript in the run folder (the run did not close cleanly?). The run log counts "
                          f"{_plural(len(facts.turn_index), 'turn')} for it.", ""]
        out.append("Every entry of the lane's transcript, in order. A step is one turn of the lane's model: each tool call it "
                   "made, and what the transcript kept of the call's output.")
        out.append("")
        if head.plan:
            out += ["The lane's last plan:", "", fenced(self.clean(head.plan)), ""]
        if head.result:
            out += ["How the lane ended:", "", fenced(self.clean(head.result)), ""]
        if not head.actions:
            out += ["The transcript has no entries: the lane took no turn.", ""]
        for action in head.actions:
            out += self._action(action)
        out += self._files(head)
        return out

    def _action(self, action: ActionLine) -> list[str]:
        who = _WHO.get(action.by, inline(action.by) if action.by else "unknown")
        kind = inline(action.kind) if action.kind else "entry"
        if action.alert:
            kind += f" ({inline(action.alert)})"
        out = [f"**{_clock(run_time(action.at))} · turn {action.turn} · {who} · {kind}**", ""]
        if action.calls:
            for number, call in enumerate(action.calls, start=1):
                out += [f"Tool call {number} of {len(action.calls)}:", "", fenced(self.clean(call.text)), ""]
                if call.output:
                    out += ["Its output, as the transcript kept it:", "", fenced(self.clean(call.output)), ""]
            skipped = _NOT_RUN.search(action.text)  # the driver's note on the calls it did not run
            if skipped:
                count, why = int(skipped.group(1)), self.clean(skipped.group(2))
                out += [f"{_plural(count, 'more tool call')} the model asked for did not run: {inline(why)}.", ""]
            return out
        out += [fenced(self.clean(action.text)), ""]
        if action.output:
            label = {"step": "Output, as the transcript kept it:", "alert": "Its reason:"}.get(action.kind, "With it:")
            out += [label, "", fenced(self.clean(action.output)), ""]
        return out

    def _files(self, head: LaneRecord) -> list[str]:
        if not head.files:
            return []
        out = ["Files changed in this lane's workspace (the newest change to each):", ""]
        for change in head.files:
            by = "by you, in a take-over" if change.by == "player" else "by the lane"
            out.append(f"- {code(change.file)} · {inline(change.status or 'changed')} · turn {change.turn} · {by}")
            if change.diff:
                out += ["", fenced(self.clean(change.diff), "diff"), ""]
        return [*out, ""]


_NOT_RUN = re.compile(r"\((\d+) tool calls? not run: ([^()]*)\)\s*$")


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""
