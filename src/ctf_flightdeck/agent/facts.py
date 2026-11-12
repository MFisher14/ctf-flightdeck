"""What flightdeck knows of a lane's handout before the lane's first model call, and the light
model's first look at it: the route and recon jobs of [light] jobs (light.py).

The facts (handout_facts): for each file the board names (at most MAX_FACT_FILES, as the brief
names them), its name, its size, what `file -b` says of it, and an excerpt of its printable
strings. `file` runs in the lane's workspace, so under Docker inside the lane's own container:
when lanes run in Docker, a parser of hostile files never runs on the player's machine (D17);
on the host runtime it runs as the player, as an L1 engine does. It runs once for all the files,
each name quoted and after `--`, within FACTS_SECONDS, and no file of the handout is ever run.
Sizes and strings are read by flightdeck itself, the way the search for planted flags reads the
handout (agent/driver._plant: no symlink followed, at most STRINGS_BYTES of each file): a run
of printable characters needs no parser and no tool, so a lane image without binutils
(debian:bookworm-slim) gets them too. When `file` cannot say anything (it is not in the image,
it took too long), the facts still have names, sizes and strings, and the run says why, once.

The first look (FirstLooks.start): once a lane's workspace is ready, the facts, then route's
questions and recon's brief, each one try within its light engine's own time limit ([light]
timeout). Route asks which specialist family the challenge suits, and its category only where
the board names none flightdeck knows (platform/manual.category_code, as the rules read it:
light.RulesLight); the board's category is never changed: the answer is a guess, shown as one
("osint?"). Route never asks whether the challenge needs a live instance (that is the rules',
from the board's URLs and the description) and opens nothing. Recon writes a first-pass brief
from the same facts. One first look per challenge: a fork of a lane, or a lane started again on
the challenge, takes the one already made (or under way).

Nothing waits for it. At the lane's first model call (FirstLooks.opening) the lane takes what is
back: the family and the category guess as triage lines, and the brief, every match of the flag
format in it replaced and the rest cut at a line to light.BRIEF_CHARS. They go in a fenced block
of the lane's opening brief (prompts.brief's `recon`), which every fresh context of the lane (an
escalation, a refresh) repeats as it was, so the cached prefix stays the same. What is not back
then is left out of the lane for good (never added mid-lane), said on the lane and once in the
run; route's answers still reach the challenge's record, the console and the event log when
they come (Deck.record_route). Every job's spend counts on the lane that started the first look,
as the hint judge's does. A failure, a refusal, a timeout, an answer outside the options or an
unsure one leaves the rules' answer (no family, no guess, no brief), said once in the run for
each kind; nothing is asked again or moved to another model.

Everything the facts and the light model's answers hold is untrusted: the light model gets the
facts inside the harness's fence (light.render), and the brief goes to the lane inside a fence
of its own, after the challenge's.
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
from collections.abc import Coroutine, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..core.driver import TurnReport
from ..light import (
    BRIEF_CHARS,
    CATEGORY,
    ERROR,
    FAMILY,
    FAMILY_CHOICES,
    NO_ANSWER,
    OUTSIDE,
    RECON,
    REFUSED,
    ROUTE,
    TIMEOUT,
    UNSURE,
    Answer,
    Question,
    RulesLight,
    shown,
)
from . import prompts
from .workspace import WorkspaceError, open_inside

if TYPE_CHECKING:
    from ..core.deck import Deck
    from ..core.model import Challenge
    from ..light import Light, Lights
    from .workspace import Workspace

MAX_FACT_FILES = prompts.MAX_BRIEF_FILES  # files a first look reads, the first the board names
FACTS_SECONDS = 10.0  # the one `file` run over the handout, at most
FILE_CHARS = 200  # of what `file` says of one file
STRINGS_MIN = 6  # characters of a run of printable ones, as `strings -n 6` takes it
STRINGS_SHOWN = 8  # runs shown of one file: the first ones in it, each once
STRING_CHARS = 80  # of each run
STRINGS_BYTES = 256 * 1024  # of each file, read for its strings
STRINGS_TOTAL = 8 * 1024 * 1024  # of all of them
NO_FILE = 127  # the facts command's status when the workspace has no `file`
NO_FILE_SAID = "flightdeck: no file command here"
FLAG_REMOVED = "[flag-shaped text removed]"
_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{%d,}" % STRINGS_MIN)
FAMILY_NAMES = {choice.id: choice.name for choice in FAMILY_CHOICES}
WHAT = {  # a failed job, in the player's warning
    REFUSED: "declined",
    ERROR: "failed",
    TIMEOUT: "took too long",
    NO_ANSWER: "gave no answer",
    OUTSIDE: "answered with none of the options",
    UNSURE: "was unsure",
}
STANDS = {  # what stands instead of a failed job's answer
    FAMILY.key: "no family is recorded",
    CATEGORY.key: "the challenge keeps the board's category, with no guess",
    RECON: "the lane's brief goes without a first look",
}


# ---------------------------------------------------------------------- the facts


@dataclass(frozen=True)
class FileFacts:
    """One handout file, as the light model reads it (light.render_challenge's files)."""

    name: str
    size: int | None = None  # None: not in the workspace as a regular file
    file: str = ""  # what `file -b` says of it; "" when the facts have none (HandoutFacts.problem)
    strings: tuple[str, ...] = ()

    def data(self) -> dict[str, Any]:
        item: dict[str, Any] = {"name": self.name, "size": self.size if self.size is not None else "not in the workspace"}
        if self.file:
            item["file"] = self.file
        if self.strings:
            item["strings"] = list(self.strings)
        return item


@dataclass(frozen=True)
class HandoutFacts:
    """A lane's handout as the light model reads it: the files' facts, how many more the board
    names than were read, and why `file` said nothing ("" when it ran)."""

    files: tuple[FileFacts, ...] = ()
    more: int = 0
    problem: str = ""

    def data(self) -> list[Any]:
        items: list[Any] = [f.data() for f in self.files]
        if self.more:
            items.append(f"and {self.more} more file{'s' if self.more > 1 else ''}, not read")
        return items


async def handout_facts(workspace: Workspace, names: Sequence[str], *, timeout: float = FACTS_SECONDS) -> HandoutFacts:
    """The facts of the files the board names (`names`, relative paths in the workspace), at
    most MAX_FACT_FILES of them. Never raises for what the workspace or `file` did: what could
    not be said is HandoutFacts.problem, or a file's missing size."""
    shown_names = [str(name) for name in names[:MAX_FACT_FILES]]
    read = await asyncio.to_thread(_read_all, workspace.root, shown_names)
    there = [name for name, (size, _) in zip(shown_names, read) if size is not None]
    said, problem = await _file_says(workspace, there, timeout)
    files = tuple(FileFacts(name, size, said.get(name, ""), strings) for name, (size, strings) in zip(shown_names, read))
    return HandoutFacts(files, max(0, len(names) - len(shown_names)), problem)


def _read_all(root, names: Sequence[str]) -> list[tuple[int | None, tuple[str, ...]]]:
    """(size, strings) of each file, read from root without following a symlink: (None, ())
    for one that is not a regular file there. In a thread."""
    budget = STRINGS_TOTAL
    out: list[tuple[int | None, tuple[str, ...]]] = []
    for name in names:
        try:
            fd = open_inside(root, name.split("/"))
            with os.fdopen(fd, "rb") as file:
                size = os.fstat(file.fileno()).st_size
                data = file.read(min(STRINGS_BYTES, budget)) if budget > 0 else b""
        except (OSError, ValueError):  # gone, a directory, a link, not a regular file, a name no path can hold
            out.append((None, ()))
            continue
        budget -= len(data)
        out.append((size, strings(data)))
    return out


def strings(data: bytes) -> tuple[str, ...]:
    """The first STRINGS_SHOWN runs of at least STRINGS_MIN printable ASCII characters (a tab
    too) in `data`, each once and cut to STRING_CHARS: an excerpt of `strings -n 6`."""
    found: dict[str, None] = {}
    for match in _PRINTABLE.finditer(data):
        text = match.group().decode("ascii").strip()
        if len(text) < STRINGS_MIN:
            continue
        if len(text) > STRING_CHARS:
            text = text[: STRING_CHARS - 3] + "..."
        found.setdefault(text)
        if len(found) == STRINGS_SHOWN:
            break
    return tuple(found)


def file_command(names: Sequence[str]) -> str:
    """The one command that asks `file -b` about each name, in order, each answer ended by a
    NUL. Every name is quoted for the shell and given after `--`: a name is only ever an
    argument to `file`, never a command or an option."""
    quoted = " ".join(shlex.quote(name) for name in names)
    return (
        f"command -v file >/dev/null 2>&1 || {{ printf '%s\\n' {shlex.quote(NO_FILE_SAID)}; exit {NO_FILE}; }}\n"
        f"for f in {quoted}; do file -b -- \"$f\" 2>&1 | head -c {FILE_CHARS * 4}; printf '\\0'; done"
    )


async def _file_says(workspace: Workspace, names: Sequence[str], timeout: float) -> tuple[dict[str, str], str]:
    """What `file -b` says of each name, run in the workspace, and why it said nothing ("")."""
    if not names:
        return {}, ""
    where = f"the lane's container (image {workspace.image})" if isinstance(getattr(workspace, "image", None), str) else "the lane's workspace"
    try:
        result = await workspace.run(file_command(names), timeout=timeout)
    except (WorkspaceError, ValueError) as exc:
        return {}, f"`file` could not run in {where}: {shown(str(exc))}"
    if result.timed_out:
        return {}, f"`file` took longer than {timeout:g} s in {where}"
    if result.exit_code == NO_FILE and result.output.startswith(NO_FILE_SAID.encode()):
        return {}, f"`file` is not installed in {where}"
    parts = result.output.split(b"\0")
    if result.exit_code != 0 or len(parts) != len(names) + 1 or parts[-1].strip():
        return {}, f"what `file` printed in {where} could not be read (exit status {result.exit_code})"
    return {name: _said(part) for name, part in zip(names, parts)}, ""


def _said(raw: bytes) -> str:
    """One answer of `file -b`: its first line, at most FILE_CHARS characters (untrusted: it
    can quote the file)."""
    lines = raw.decode("utf-8", "replace").strip().splitlines()
    line = lines[0].strip() if lines else ""
    return line if len(line) <= FILE_CHARS else line[: FILE_CHARS - 3] + "..."


def challenge_data(challenge: Challenge, facts: HandoutFacts, urls: Sequence[str]) -> dict[str, Any]:
    """The challenge as a route or recon job reads it (light.CHALLENGE_KEYS): as the board
    gives it, with its handout's facts."""
    return {
        "name": challenge.name,
        "category": challenge.category,
        "points": challenge.points,
        "solves": challenge.solves,
        "description": challenge.description,
        "files": facts.data(),
        "urls": list(urls),
    }


def board_names_category(challenge: Challenge) -> bool:
    """Whether the board names a category flightdeck knows, as the rules read it: then route
    never asks the light model for one."""
    return RulesLight().choose(ROUTE, {"category": challenge.category}, CATEGORY, CATEGORY.choices).ok


# ---------------------------------------------------------------------- the first look's text


def first_look(family: str, category: str, brief: str, pattern: re.Pattern[str]) -> str:
    """The first look as a lane's opening brief holds it (prompts.brief's `recon`): the family
    and the category guess as triage lines, then the brief with every match of the flag format
    replaced by FLAG_REMOVED and cut at a line to BRIEF_CHARS. "" when there is nothing, or when
    the flag format matches the result anyway (flightdeck's own words, say): a lane never gets a
    flag-shaped string from the light model."""
    lines = []
    if family:
        lines.append(f"Specialist it suits: {family} ({FAMILY_NAMES.get(family, family)})")
    if category:
        lines.append(f"Category: {category}? (a guess: the board names no category flightdeck knows)")
    if brief.strip():
        lines.append(cut_at_line(pattern.sub(FLAG_REMOVED, brief).strip(), BRIEF_CHARS))
    text = "\n".join(lines)
    return "" if text and pattern.search(text) else text


def cut_at_line(text: str, limit: int) -> str:
    """`text` in at most `limit` characters: cut at the last line break that fits (else the
    last space), with a line saying it was cut."""
    if len(text) <= limit:
        return text
    note = f"\n[cut: the light model's brief ran to {len(text):,} characters]"
    head = text[: max(0, limit - len(note))]
    at = head.rfind("\n")
    if at <= 0:
        at = head.rfind(" ")
    if at > 0:
        head = head[:at]
    return head.rstrip() + note


# ---------------------------------------------------------------------- the first look


class Look:
    """One challenge's first look: its tasks, each a light job (route's questions, recon's
    brief) after the facts, and the lane it was started for (its spend and its notes are that
    lane's)."""

    def __init__(self, challenge: Challenge, lane_id: str, route: Light | None, recon: Light | None) -> None:
        self.challenge = challenge
        self.lane_id = lane_id
        self.route_engine = route
        self.recon_engine = recon
        self.facts: asyncio.Task[HandoutFacts] | None = None
        self.route: asyncio.Task[tuple[str, str]] | None = None  # (family, category guess)
        self.recon: asyncio.Task[str] | None = None  # the brief as the light model wrote it ("" when it failed)

    def tasks(self) -> list[asyncio.Task]:
        return [task for task in (self.facts, self.route, self.recon) if task is not None]


def _result(task: asyncio.Task | None):
    """A finished task's result, else None (not back yet, cancelled, or broken)."""
    if task is None or not task.done() or task.cancelled() or task.exception() is not None:
        return None
    return task.result()


class FirstLooks:
    """The first looks of a run's lanes (each driver has one): one per challenge, and what the
    run has said once."""

    def __init__(self, errors: list[str] | None = None) -> None:
        self._looks: dict[str, Look] = {}  # challenge id -> its first look
        self._said: set[str] = set()  # what the run has told the player once
        self.errors = errors if errors is not None else []  # a first look that broke (a flightdeck bug): the driver's, shown when the run ends

    def start(self, lights: Lights | None, deck: Deck, lane_id: str, challenge: Challenge, workspace: Workspace,
              files: Sequence[str], urls: Sequence[str]) -> Look | None:
        """The challenge's first look, started now in `workspace` (ready) for `lane_id`, or the
        one already made or under way; None when no light engine does route or recon. Returns
        at once: the work is in tasks of its own."""
        if lights is None:
            return None
        route, recon = _engine(lights, ROUTE), _engine(lights, RECON)
        if route is None and recon is None:
            return None
        look = self._looks.get(challenge.id)
        if look is not None:
            return look
        look = self._looks[challenge.id] = Look(challenge, lane_id, route, recon)
        loop = asyncio.get_running_loop()
        name = f"flightdeck first look {lane_id}"
        look.facts = loop.create_task(self._guarded(deck, look, "facts", self._facts(deck, look, workspace, files),
                                                    HandoutFacts()), name=f"{name} facts")
        if route is not None:
            look.route = loop.create_task(self._guarded(deck, look, ROUTE, self._route(deck, look, route, urls), ("", "")),
                                          name=f"{name} route")
        if recon is not None:
            look.recon = loop.create_task(self._guarded(deck, look, RECON, self._recon(deck, look, recon, urls), ""),
                                          name=f"{name} recon")
        return look

    def opening(self, look: Look, deck: Deck, lane_id: str, pattern: re.Pattern[str]) -> str:
        """At a lane's first model call: the first look's text for its brief, from what is back
        now ("" when nothing is). What is not back is left out of this lane for good: said on
        the lane, and once in the run."""
        family, category = _result(look.route) or ("", "")
        brief = _result(look.recon) or ""
        text = first_look(family, category, brief, pattern)
        late = [job for job, task in ((ROUTE, look.route), (RECON, look.recon)) if task is not None and not task.done()]
        parts = []
        if family or category:
            parts.append("route")
        if brief and text:
            parts.append("recon")
        if text:
            deck.note(lane_id, f"its opening brief holds the light model's first look at the handout ({' and '.join(parts)}, "
                               f"{len(text):,} characters, fenced as data)")
        elif family or category or brief:
            deck.note(lane_id, "the light model's first look is left out of its brief: the flag format matches it")
        if late:
            jobs, were = " and ".join(late), "were" if len(late) > 1 else "was"
            deck.note(lane_id, f"the light model's {jobs} {were} not back by its first model call: its brief goes without "
                               f"{'them' if len(late) > 1 else 'it'}")
            self._once(deck, "late", (
                f"{lane_id}: the light model's {jobs} {were} not back by the lane's first model call, so the lane started "
                f"without {'them' if len(late) > 1 else 'it'}; a lane never waits for the light model, and nothing is added "
                "to a brief later (route's answers still show on the board when they come). Said once."),
                look, job=jobs)
        return text

    def done(self, challenge_id: str) -> bool:
        """Whether the challenge's first look has started and every job of it is back."""
        look = self._looks.get(challenge_id)
        return look is not None and all(task.done() for task in look.tasks())

    async def aclose(self) -> None:
        """Cancel every first look still under way (the run is ending)."""
        tasks = [task for look in self._looks.values() for task in look.tasks() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------------------ the jobs

    async def _facts(self, deck: Deck, look: Look, workspace: Workspace, files: Sequence[str]) -> HandoutFacts:
        facts = await handout_facts(workspace, files)
        if facts.problem:
            self._once(deck, f"facts: {facts.problem}", (
                f"{look.lane_id}: {facts.problem}, so the light model's first look at the handout has its files' names, "
                "sizes and strings but not what `file` says of them. Said once."), look, job="facts")
        return facts

    async def _route(self, deck: Deck, look: Look, engine: Light, urls: Sequence[str]) -> tuple[str, str]:
        """Route's questions: the family, and the category where the board names none
        flightdeck knows. An answer is recorded on the challenge (never its category), and a
        failed one leaves the rules' answer: nothing."""
        assert look.facts is not None
        data = challenge_data(look.challenge, await look.facts, urls)
        asks: list[Question] = [FAMILY] if board_names_category(look.challenge) else [CATEGORY, FAMILY]
        answers = await asyncio.gather(*(engine.ask_choice(ROUTE, data, question, question.choices) for question in asks))
        found = {FAMILY.key: "", CATEGORY.key: ""}
        for question, answer in zip(asks, answers):
            self._spent(deck, look, answer, f"the light model's route, its {question.key} question ({engine.label})", engine)
            if answer.ok and answer.choice:
                found[question.key] = answer.choice
            else:
                self._failed(deck, look, f"route's {question.key} question", question.key, answer, engine)
        family, category = found[FAMILY.key], found[CATEGORY.key]
        if family or category:
            deck.record_route(look.challenge.id, family=family, category=category, by=engine.label, lane_id=look.lane_id)
        return family, category

    async def _recon(self, deck: Deck, look: Look, engine: Light, urls: Sequence[str]) -> str:
        """Recon's brief, as the light model wrote it (untrusted), or "" when it failed."""
        assert look.facts is not None
        data = challenge_data(look.challenge, await look.facts, urls)
        answer = await engine.write_brief(data)
        self._spent(deck, look, answer, f"the light model's recon ({engine.label})", engine)
        if not answer.ok:
            self._failed(deck, look, "recon's brief", RECON, answer, engine)
            return ""
        return answer.text

    async def _guarded(self, deck: Deck, look: Look, job: str, work: Coroutine[Any, Any, Any], neutral: Any) -> Any:
        """`work`, or `neutral` when it broke (a flightdeck bug): the lane never sees it; the
        run's errors and the player do, once."""
        try:
            return await work
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            problem = f"{look.lane_id}: the light model's first look ({job}) broke: {type(exc).__name__}: {exc}"
            self.errors.append(problem)
            self._once(deck, f"broke: {job}", f"{shown(problem)}. The rules' answer stands. Said once.", look, job=job)
            return neutral

    # ------------------------------------------------------------------ what the run is told

    def _spent(self, deck: Deck, look: Look, answer: Answer, why: str, engine: Light) -> None:
        """A job's spend, on the lane it ran for (also once that lane has ended: spend only)."""
        if answer.spent and look.lane_id in deck.lanes:
            deck.report(look.lane_id, TurnReport(turn=False, tokens=answer.tokens, cached_tokens=answer.cached_tokens,
                                                 dollars=answer.cost, why=why, model=engine.model or None))

    def _failed(self, deck: Deck, look: Look, job: str, key: str, answer: Answer, engine: Light) -> None:
        kind = "for an unsure answer" if answer.failure == UNSURE else "for this kind of failure"
        self._once(deck, f"{key}: {answer.failure}", (
            f"{look.lane_id}: the light model ({engine.label}) {WHAT.get(answer.failure, 'failed')} on {job}: "
            f"{shown(answer.why)}. The rules' answer stands: {STANDS[key]}. Said once {kind}."),
            look, job=key, engine=engine, failure=answer.failure)

    def _once(self, deck: Deck, key: str, text: str, look: Look, *, job: str, engine: Light | None = None,
              failure: str = "") -> None:
        if key in self._said:
            return
        self._said.add(key)
        data: dict[str, object] = {"source": "light", "job": job, "lane": look.lane_id}
        if engine is not None:
            data.update(engine=engine.engine, model=engine.model)
        if failure:
            data["failure"] = failure
        deck.warn(text, challenge=look.challenge.id, data=data)


def _engine(lights: Lights, job: str) -> Light | None:
    engine = lights.get(job)
    return engine if engine is not None and engine.does(job) else None


def first_look_notes(lights: Lights | None) -> list[str]:
    """The run's lines for the player about route and recon: what each light engine does at a
    lane's start, and that nothing waits for it."""
    if lights is None:
        return []
    jobs: dict[int, tuple[Light, list[str]]] = {}
    for job in (ROUTE, RECON):
        engine = _engine(lights, job)
        if engine is not None:
            jobs.setdefault(id(engine), (engine, []))[1].append(job)
    lines = []
    for engine, done in jobs.values():
        what = []
        if ROUTE in done:
            what.append("routes each challenge (the specialist family it suits, and its category where the board names "
                        "none flightdeck knows, shown as a guess, never in place of the board's)")
        if RECON in done:
            what.append("writes a first look at each challenge's handout for its lane's opening brief (fenced as data, "
                        "flag-shaped text removed)")
        line = (f"light model: {engine.label} " + " and ".join(what) + " at a lane's start, from what `file` and the "
                "handout's strings say; a lane never waits for it: what is not back by its first model call is left "
                "out of its brief")
        price, free = getattr(engine, "price", None), getattr(engine, "free", False)
        if engine.engine == "anthropic" and price is None:
            line += ("; no price for it in your config, so its calls are unpriced: a dollar-capped lane asks you once "
                     "before it carries on without its cap")
        elif engine.engine == "openai" and price is None and not free:
            line += ("; no price for it in your config, so its calls are unpriced unless the API reports their cost: a "
                     "dollar-capped lane may ask you once")
        elif engine.engine == "decider" and not free:
            line += "; its server is not on this machine, so its calls' cost is unknown: a dollar-capped lane may ask you once"
        lines.append(line)
    return lines
