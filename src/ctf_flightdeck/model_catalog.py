"""The model catalog (models.toml), and which of its models fit this machine for each role.

flightdeck's model roles:

- lanes: the tool loop, on [api] and the [models] ladder (weakest first; escalation climbs it).
  A lane needs reliable tool calls.
- light: the light role's small classification jobs ([light]; today the hint judge). The rules
  by default; a model is measured with `flightdeck eval-local` before it is switched on.

Coding-agent lanes (`play --agent claude|codex`) bring their own models ([agents]): not here.

This recommends; it never picks for the player and never changes a config. Local open-weight
models come first where this machine can run them (no provider's safety classifier stands
between them and security work, and they cost nothing), then the APIs.

What fits (an estimate, never a measurement): a local model needs its weights (its size on
disk, as the benchmark behind docs/MODELS.md recorded it, or for a model Ollama here has
pulled and the catalog has no size for, the size Ollama gives it) plus CONTEXT_ALLOWANCE for
its context and the runtime's own buffers: 6 GiB for a lane, whose context grows to 50,000
prompt tokens before the driver refreshes it (agent/driver.py COMPACT_AT; a typical 8B model's
16-bit KV cache for that many tokens is about 6 GiB), and 2 GiB for the light role, whose
prompts are a few hundred tokens. The real need depends on the runtime, its context length
setting and the model's attention layout. It fits when that is at most what this machine gives
local models (budget()):

- Apple Silicon: two thirds of unified memory. The GPU shares it with macOS, the Docker lanes
  and every other app, and macOS lets the GPU use only part of it by default.
- an NVIDIA GPU: the memory of the largest one (runtimes can also split a model across GPUs,
  or onto the CPU, but flightdeck counts one GPU).
- neither: half of the memory, and local models run on the CPU, slowly: lanes lead with an
  API, and the light role with the rules or a small model.

A build with no size, or a machine whose memory (or GPU) is unknown, is "cannot tell": never a
guess. MLX runs on Apple Silicon only.

Each build (a model on one runtime) carries what was found serving it: the arguments its MLX
server was measured with (server_args, printed in the command that serves it), the [light]
thinking its light results were measured with when it is not flightdeck's default (thinking),
the roles it should not serve and why (not_for: it is never offered for them; a build that
measured badly for a role is not for it), and its measured results (measured, from
docs/MODELS.md). A model's results and settings differ by runtime. A model is offered for the
roles at least one of its builds serves (LocalModel.offered_for).

The light role is several jobs: those a run gives the light model ([light] jobs: the judge,
route, recon and flagcheck), and hint and summary, which only eval-local asks. A build with
per-job results (jobs: eval-local's figures, each job as a run uses it, on the case set the
catalog's [eval] table describes) is offered for each run job it measured no worse at than
flightdeck's default for that job (offered_jobs()), and for the light role when it is offered
for one; its light line is written from those figures (jobs_line()). The default is what a run
does with no light model: the judge's alert stands as the rules raised it, flagcheck is the
planted-flag hold alone, route's instance is always the rule's and its category the board's
where the board names one, so a model is asked only for the category where the board names none
and for the specialist family, and nothing writes a brief (recon). Where a run with no model has
no answer (that category, the family, the brief), a right answer is better than none and a
wrong one worse, since it goes into the lane's opening brief (agent/facts.first_look): such a
job is worse when its wrong answers outnumber its right ones, as eval-local's in-a-run rows
count a true alert taken down or a real flag held against the model. hint is never a run's (a
run uses the rules), so it decides nothing here. A build measured only on the earlier 58-case
set (hint and judge, 44 scored) keeps that set's verdict, below the rules' 38 is not for the
light role, and is offered for the judge alone, the one run job that set measured.
"""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType

from .config import MLX_URL, OLLAMA_URL, RUN_JOBS
from .hardware import GIB, MLX, OLLAMA, RUNTIME_NAMES, Machine, gib
from .pricing import Price

CATALOG_FILE = "models.toml"
MODELS_DOC = "docs/MODELS.md"  # the measured results, written from the benchmark
LANES, LIGHT = ROLES = ("lanes", "light")
BUILDS = (OLLAMA, MLX)  # the runtimes a local entry can name, in the order they are shown
SERVER_URLS = {OLLAMA: OLLAMA_URL, MLX: MLX_URL}  # where flightdeck reaches each runtime's server
CONTEXT_ALLOWANCE = {LANES: 6 * GIB, LIGHT: 2 * GIB}  # bytes added to a model's weights (see the module doc)
APPLE_SHARE = (2, 3)  # of unified memory, on Apple Silicon
CPU_SHARE = (1, 2)  # of memory, with no GPU flightdeck can use
PROVIDERS = ("anthropic", "openrouter")  # an [[api]] entry's provider: its details come from setup.py

APPLE, NVIDIA, CPU, UNKNOWN = "apple silicon", "nvidia gpu", "cpu", "unknown"  # where local models would run
SIZE_CATALOG, SIZE_SERVER = "catalog", "server"  # where a build's size came from: models.toml, or its server here
FITS, TOO_BIG, CANNOT_TELL, NOT_HERE = "fits", "too big", "cannot tell", "not on this machine"
LOCAL, API, RULES = "local", "api", "rules"  # what a role's advice leads with

JUDGE, ROUTE, RECON, FLAGCHECK = RUN_JOBS  # the jobs a run gives the light model ([light] jobs)
# A [local.<runtime>.jobs] table's keys, and [eval]'s: hint (eval-local only), the judge, route's two
# questions a run asks a model (its category where the board names none, and the family), recon and
# flagcheck.
JOB_KEYS = ("hint", "judge", "category", "family", "recon", "flagcheck")
COUNTED = ("category", "family", "recon")  # answers a run has none of without a model: right and wrong
EARLIER_SET = (JUDGE,)  # the run jobs the earlier 58-case set measured (a light result with no jobs table)

_LOCAL_KEYS = ("id", "name", "family", "parameters", "license", "roles", *BUILDS)
_LOCAL_REQUIRED = ("id", "name", "family", "parameters", "license", "roles")
_BUILD_KEYS = ("model", "quantization", "size_bytes", "server_args", "thinking", "not_for", "measured", "jobs")
# [eval]: each job's case count, flightdeck's default on them (right answers with no light model:
# the rules for hint, a run without one for the judge, route's category and flagcheck) and, for
# route's category, how many a run asks a model; the family and recon have no default
_EVAL_SHAPE = {"hint": ("cases", "default"), "judge": ("cases", "default"), "category": ("cases", "default", "asked"),
               "family": ("cases",), "recon": ("cases",), "flagcheck": ("cases", "default")}
SET_BY_COMMAND = ("--model", "--host", "--port")  # mlx_lm.server arguments serve_command() sets itself
_API_KEYS = ("id", "name", "provider", "roles", "classifier", "note", "models_page")
_API_REQUIRED = ("id", "name", "provider", "roles", "classifier", "note")
_ID = re.compile(r"[a-z0-9][a-z0-9.-]*")
_PARAMETERS = re.compile(r"[0-9]+(?:\.[0-9]+)?[MB]")


class CatalogError(ValueError):
    """The catalog cannot be used; the message names the file and the entry."""


_NO_LINES: Mapping[str, str] = MappingProxyType({})


@dataclass(frozen=True)
class Scored:
    """One job of the case set ([eval]): its cases, and flightdeck's default on them."""

    cases: int
    default: int | None = None  # right with no light model (the rules for hint, a run without one); None: no answer
    asked: int | None = None  # route's category only: the cases a run asks a model (the board names no category it knows)


EvalSet = Mapping[str, Scored]  # JOB_KEYS -> Scored: the case set behind every jobs table


@dataclass(frozen=True)
class Counts:
    """Answers where a run asks the model and has none without it: right ones, and wrong ones
    (which go into the lane's opening brief); the rest of the cases got no answer."""

    right: int
    wrong: int


@dataclass(frozen=True)
class JobResults:
    """A build's light jobs as a run uses them (a [local.<runtime>.jobs] table), on [eval]'s cases."""

    hint: int  # right (eval-local only: a run uses the rules)
    judge: int  # right in a run: asked only where the rules see no action cue, it can only take an alert down
    category: Counts  # route's category, of the cases where the board names none
    family: Counts  # route's specialist family
    recon: Counts  # recon's briefs
    flagcheck: int  # right in a run: on top of the planted-flag hold, it can only hold a flag
    cases: EvalSet = MappingProxyType({})  # the case set it was scored on ([eval])


@dataclass(frozen=True)
class Build:
    """A local model as one runtime serves it."""

    runtime: str  # OLLAMA or MLX
    model: str  # the runtime's name for it: an Ollama tag, a Hugging Face repo for mlx_lm.server
    quantization: str | None = None  # None: not recorded
    size: int | None = None  # bytes of its weights on disk; None: not recorded
    server_args: tuple[str, ...] = ()  # MLX: what mlx_lm.server was measured with, after serve_command()'s own
    not_for: Mapping[str, str] = _NO_LINES  # role -> why this build should not serve it (one line)
    measured: Mapping[str, str] = _NO_LINES  # role -> a one-line result from docs/MODELS.md
    thinking: bool | None = None  # [light] thinking its light results were measured with; None: flightdeck's default
    jobs: JobResults | None = None  # the light role's jobs as a run uses them; None: not measured job by job
    light_jobs: tuple[str, ...] = ()  # the run jobs it is offered for: offered_jobs(), or the judge (EARLIER_SET)


@dataclass(frozen=True)
class LocalModel:
    id: str
    name: str
    family: str
    parameters: str  # "9.0B"
    license: str
    roles: tuple[str, ...]
    builds: tuple[Build, ...]

    def build(self, runtime: str) -> Build | None:
        return next((b for b in self.builds if b.runtime == runtime), None)

    def serves(self, build: Build) -> tuple[str, ...]:
        """The roles `build` may serve: the model's, less those the build is not for."""
        return tuple(role for role in self.roles if role not in build.not_for)

    @property
    def offered_for(self) -> tuple[str, ...]:
        """The roles it is offered for: those at least one of its builds may serve. Its roles are
        the ones the catalog considers it for; a role every build is not for is not offered."""
        return tuple(role for role in self.roles if any(role in self.serves(build) for build in self.builds))


@dataclass(frozen=True)
class ApiChoice:
    """A model API. Its endpoint, ladder and prices come from setup.py (what init writes)."""

    id: str
    name: str
    provider: str  # anthropic | openrouter
    roles: tuple[str, ...]
    classifier: bool  # the provider's safety classifier can decline security work
    note: str
    models_page: str  # "" when the catalog names its models
    base_url: str
    key_env: str
    ladder: tuple[str, ...]  # weakest first; () when the player chooses (OpenRouter)
    prices: Mapping[str, Price]  # dollars per million tokens: per ladder model, its refusal fallback's, the light model
    light_model: str  # the model `init --light` writes for it; "" when the player chooses


@dataclass(frozen=True)
class Catalog:
    local: tuple[LocalModel, ...]
    api: tuple[ApiChoice, ...]
    eval: EvalSet = MappingProxyType({})  # [eval]: the case set behind the builds' jobs tables; empty: none

    def get(self, ident: str) -> LocalModel | ApiChoice | None:
        return next((e for e in (*self.local, *self.api) if e.id == ident), None)

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(e.id for e in (*self.local, *self.api))


# ---------------------------------------------------------------------- loading and checking


def load_catalog(path: Path | None = None) -> Catalog:
    """The catalog in `path`, or the one shipped with flightdeck. CatalogError says what is wrong."""
    where = str(path) if path is not None else f"ctf_flightdeck/{CATALOG_FILE}"
    try:
        raw = Path(path).read_text(encoding="utf-8") if path is not None else (
            files("ctf_flightdeck").joinpath(CATALOG_FILE).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise CatalogError(f"cannot read the model catalog {where}: {exc}") from None
    return parse_catalog(raw, where)


def parse_catalog(text: str, where: str = CATALOG_FILE) -> Catalog:
    """Check a catalog given as TOML text; `where` names it in errors."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise CatalogError(f"the model catalog {where} is not valid TOML: {exc}") from None
    extra = [key for key in data if key not in ("local", "api", "eval")]
    if extra:
        raise CatalogError(f"{where}: unknown top-level key {', '.join(extra)} (known: local, api, eval)")
    local_entries, api_entries = data.get("local", []), data.get("api", [])
    for table, entries in (("local", local_entries), ("api", api_entries)):
        if not isinstance(entries, list):
            raise CatalogError(f"{where}: {table} must be a list of [[{table}]] tables")
    if not local_entries:
        raise CatalogError(f"{where} has no [[local]] entries")
    cases = _eval(data["eval"], f"{where}: [eval]") if "eval" in data else MappingProxyType({})
    local = tuple(_local(entry, f"{where}: [[local]] entry {n}", cases) for n, entry in enumerate(local_entries, 1))
    api = tuple(_api(entry, f"{where}: [[api]] entry {n}") for n, entry in enumerate(api_entries, 1))
    seen: dict[str, str] = {}
    for kind, entries in (("local", local), ("api", api)):
        for n, entry in enumerate(entries, 1):
            here = f"[[{kind}]] entry {n}"
            if entry.id in seen:
                raise CatalogError(f"{where}: id {entry.id!r} is used twice: by {seen[entry.id]} and {here}")
            seen[entry.id] = here
    return Catalog(local, api, cases)


def _count(value: object) -> bool:
    """A count of cases or answers: a whole number, 0 or more (never a boolean)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _eval(table: object, where: str) -> EvalSet:
    """[eval]: for each of JOB_KEYS, its cases and the default _EVAL_SHAPE gives it, each in range."""
    if not isinstance(table, dict):
        raise CatalogError(f"{where} must be a table: one entry per job, {', '.join(JOB_KEYS)}")
    unknown = [key for key in table if key not in JOB_KEYS]
    missing = [key for key in JOB_KEYS if key not in table]
    if unknown or missing:
        raise CatalogError(f"{where}: " + "; ".join(part for part in (
            f"unknown job {', '.join(unknown)}" if unknown else "", f"missing {', '.join(missing)}" if missing else "")
            if part) + f" (it has one entry per job: {', '.join(JOB_KEYS)})")
    out = {}
    for key in JOB_KEYS:
        entry, shape = table[key], _EVAL_SHAPE[key]
        if not isinstance(entry, dict) or sorted(entry) != sorted(shape) or not all(_count(v) for v in entry.values()):
            raise CatalogError(f"{where}: {key} must be {{ {', '.join(f'{k} = N' for k in shape)} }}, each a whole number "
                               "of cases, 0 or more")
        cases = entry["cases"]
        if cases == 0:
            raise CatalogError(f"{where}: {key}.cases must be above 0")
        over = [k for k in shape[1:] if entry[k] > cases]
        if over:
            raise CatalogError(f"{where}: {key}.{over[0]} is {entry[over[0]]}, more than its {cases} cases")
        out[key] = Scored(cases, entry.get("default"), entry.get("asked"))
    return MappingProxyType(out)


def _named(entry: object, where: str, known: tuple[str, ...], required: tuple[str, ...]) -> tuple[dict, str]:
    """The entry as a dict, and how errors name it ("... entry 2 (gpt-oss-20b)"), after
    checking it has no unknown key and every required one."""
    if not isinstance(entry, dict):
        raise CatalogError(f"{where} is not a table")
    ident = entry.get("id")
    name = f"{where} ({ident})" if isinstance(ident, str) and ident else f"{where} (no id)"
    unknown = [key for key in entry if key not in known]
    if unknown:
        raise CatalogError(f"{name}: unknown key {', '.join(unknown)} (known: {', '.join(known)})")
    missing = [key for key in required if key not in entry]
    if missing:
        raise CatalogError(f"{name}: missing {', '.join(missing)}")
    if not isinstance(ident, str) or not _ID.fullmatch(ident):
        raise CatalogError(f"{name}: id must be lower-case letters, digits, '.' and '-'")
    return entry, name


def _text(entry: dict, key: str, name: str) -> str:
    value = entry[key]
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CatalogError(f"{name}: {key} must be non-empty text without spaces around it")
    return value


def _roles(entry: dict, name: str) -> tuple[str, ...]:
    roles = entry["roles"]
    if not isinstance(roles, list) or not roles or any(r not in ROLES for r in roles) or len(set(roles)) != len(roles):
        raise CatalogError(f"{name}: roles must list each of its roles once, from {', '.join(ROLES)}")
    return tuple(roles)


def _local(entry: object, where: str, cases: EvalSet) -> LocalModel:
    entry, name = _named(entry, where, _LOCAL_KEYS, _LOCAL_REQUIRED)
    roles = _roles(entry, name)
    parameters = _text(entry, "parameters", name)
    if not _PARAMETERS.fullmatch(parameters):
        raise CatalogError(f"{name}: parameters must be a count like 9.0B or 750M")
    builds = tuple(_build(entry[runtime], runtime, name, roles, cases) for runtime in BUILDS if runtime in entry)
    if not builds:
        raise CatalogError(f"{name}: names no runtime: add [local.ollama] or [local.mlx]")
    return LocalModel(
        id=entry["id"], name=_text(entry, "name", name), family=_text(entry, "family", name), parameters=parameters,
        license=_text(entry, "license", name), roles=roles, builds=builds,
    )


def _lines(table: dict, key: str, where: str, roles: tuple[str, ...], what: str) -> Mapping[str, str]:
    """A build's table of role = "one line" (`what` the line is), for the model's roles only."""
    lines = table.get(key, {})
    if not isinstance(lines, dict):
        raise CatalogError(f"{where}: {key} must be a table of role = \"{what}\"")
    for role, text in lines.items():
        if role not in roles:
            raise CatalogError(f"{where}: {key}.{role} is not one of its roles ({', '.join(roles)})")
        if not isinstance(text, str) or not text.strip() or text != text.strip() or not text.isprintable():
            raise CatalogError(f"{where}: {key}.{role} must be one line: {what}")
    return MappingProxyType(dict(lines))


def _server_args(table: dict, runtime: str, where: str) -> tuple[str, ...]:
    if "server_args" not in table:
        return ()
    if runtime != MLX:
        raise CatalogError(f"{where}: server_args is for [local.mlx] only: mlx_lm.server serves one model, and "
                           "Ollama's one server serves them all")
    args = table["server_args"]
    if not isinstance(args, list) or not args or not all(isinstance(a, str) and a and a.isprintable() for a in args):
        raise CatalogError(f"{where}: server_args must list mlx_lm.server's arguments, each one line of text")
    clash = [a for a in args if a.split("=", 1)[0] in SET_BY_COMMAND]
    if clash:
        raise CatalogError(f"{where}: server_args sets {', '.join(clash)}; the command sets {', '.join(SET_BY_COMMAND)} itself")
    return tuple(args)


def _build(table: object, runtime: str, name: str, roles: tuple[str, ...], cases: EvalSet) -> Build:
    where = f"{name}: [local.{runtime}]"
    if not isinstance(table, dict):
        raise CatalogError(f"{where} must be a table")
    unknown = [key for key in table if key not in _BUILD_KEYS]
    if unknown:
        raise CatalogError(f"{where}: unknown key {', '.join(unknown)} (known: {', '.join(_BUILD_KEYS)})")
    if "model" not in table:
        raise CatalogError(f"{where}: missing model (the runtime's name for it)")
    model = table["model"]
    if not isinstance(model, str) or not model or any(c.isspace() or not c.isprintable() for c in model):
        raise CatalogError(f"{where}: model must be the runtime's name for it, without spaces")
    quantization = table.get("quantization")
    if quantization is not None and (not isinstance(quantization, str) or not quantization.strip()):
        raise CatalogError(f"{where}: quantization must be text, or left out when it was not recorded")
    size = table.get("size_bytes")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size <= 0):
        raise CatalogError(f"{where}: size_bytes must be a positive whole number of bytes, or left out when it was not recorded")
    server_args = _server_args(table, runtime, where)
    not_for = dict(_lines(table, "not_for", where, roles, "why this build should not serve the role"))
    measured = dict(_lines(table, "measured", where, roles, "a result from docs/MODELS.md"))
    both = [role for role in measured if role in not_for]
    if both:
        raise CatalogError(f"{where}: measured.{both[0]} and not_for.{both[0]}: a build that is not for a role is never "
                           "shown for it, with or without a result")
    thinking = table.get("thinking")
    if "thinking" in table:
        if not isinstance(thinking, bool):
            raise CatalogError(f"{where}: thinking must be true or false: the [light] thinking its light results were "
                               "measured with")
        if LIGHT not in roles:
            raise CatalogError(f"{where}: thinking is the light role's setting, and the model's roles leave it out")
    jobs, light_jobs = None, ()
    if "jobs" in table:
        if LIGHT not in roles:
            raise CatalogError(f"{where}: jobs are the light role's, and the model's roles leave it out")
        if LIGHT in measured or LIGHT in not_for:
            which = "measured" if LIGHT in measured else "not_for"
            raise CatalogError(f"{where}: {which}.light and jobs: a build measured job by job gets its light line from "
                               "its jobs (jobs_line()), so it has no line of its own")
        if not cases:
            raise CatalogError(f"{where}: jobs needs the catalog's [eval] table: the cases they were scored on, and "
                               "flightdeck's default on them")
        jobs = _jobs(table["jobs"], f"{where}: jobs", cases)
        light_jobs = offered_jobs(jobs)
        line = jobs_line(jobs, light_jobs, thinking)
        (measured if light_jobs else not_for)[LIGHT] = line
    elif LIGHT in measured:
        light_jobs = EARLIER_SET
    if thinking is not None and LIGHT in not_for:
        raise CatalogError(f"{where}: thinking is set for the light role, which this build is not for")
    return Build(runtime, model, quantization, size, server_args, MappingProxyType(not_for), MappingProxyType(measured),
                 thinking, jobs, light_jobs)


def _jobs(table: object, where: str, cases: EvalSet) -> JobResults:
    """A [local.<runtime>.jobs] table: for each of JOB_KEYS, the right answers (hint, the judge and
    flagcheck in a run) or { right = N, wrong = N } (COUNTED), within [eval]'s cases."""
    if not isinstance(table, dict):
        raise CatalogError(f"{where} must be a table: one entry per job, {', '.join(JOB_KEYS)}")
    unknown = [key for key in table if key not in JOB_KEYS]
    missing = [key for key in JOB_KEYS if key not in table]
    if unknown or missing:
        raise CatalogError(f"{where}: " + "; ".join(part for part in (
            f"unknown job {', '.join(unknown)}" if unknown else "", f"missing {', '.join(missing)}" if missing else "")
            if part) + f" (it has one entry per job: {', '.join(JOB_KEYS)})")
    values: dict[str, int | Counts] = {}
    for key in JOB_KEYS:
        value, scored = table[key], cases[key]
        room = scored.asked if scored.asked is not None else scored.cases
        if key in COUNTED:
            if not isinstance(value, dict) or sorted(value) != ["right", "wrong"] or not all(_count(v) for v in value.values()):
                raise CatalogError(f"{where}: {key} must be {{ right = N, wrong = N }}: answers right and wrong where a run "
                                   "asks it")
            if value["right"] + value["wrong"] > room:
                raise CatalogError(f"{where}: {key} has {value['right'] + value['wrong']} answers, more than the {room} "
                                   "cases a run asks it")
            values[key] = Counts(value["right"], value["wrong"])
        else:
            if not _count(value) or value > room:
                raise CatalogError(f"{where}: {key} must be a whole number of right answers, 0 to its {room} cases")
            values[key] = value
    return JobResults(**values, cases=cases)  # type: ignore[arg-type]


def offered_jobs(jobs: JobResults) -> tuple[str, ...]:
    """The run jobs a build is offered for: each it measured no worse at than flightdeck's
    default for that job (the module doc). The judge and flagcheck: right in a run at least as
    often as a run with no light model. Route (a model is asked only its category where the board
    names none, and the family) and recon: right at least as often as wrong, since a run with no
    model has no answer there and a wrong one goes into the lane's opening brief."""
    cases = jobs.cases
    better = {
        JUDGE: jobs.judge >= cases["judge"].default,
        ROUTE: jobs.category.right + jobs.family.right >= jobs.category.wrong + jobs.family.wrong,
        RECON: jobs.recon.right >= jobs.recon.wrong,
        FLAGCHECK: jobs.flagcheck >= cases["flagcheck"].default,
    }
    return tuple(job for job in RUN_JOBS if better[job])


JOB_NAMES = {JUDGE: "the judge", ROUTE: "route", RECON: "recon", FLAGCHECK: "flagcheck"}


def _and(words: list[str], joint: str = "and") -> str:
    return words[0] if len(words) == 1 else f"{', '.join(words[:-1])} {joint} {words[-1]}"


def jobs_line(jobs: JobResults, offered: tuple[str, ...], thinking: bool | None = None) -> str:
    """A build's light line, written from its jobs table: the run jobs it is for and not for,
    then each job's figures beside flightdeck's default (one line)."""
    left = [job for job in RUN_JOBS if job not in offered]
    if not offered:
        head = f"worse than no model at {_and([JOB_NAMES[j] for j in left])}"
    else:
        head = f"for {_and([JOB_NAMES[j] for j in offered])}"
        if left:
            head += f"; not {_and([JOB_NAMES[j] for j in left], 'or')}, where it did worse than no model"
    cases = jobs.cases
    judge, category, family, recon = cases["judge"], cases["category"], cases["family"], cases["recon"]
    flagcheck, hint = cases["flagcheck"], cases["hint"]
    route_right, route_wrong = jobs.category.right + jobs.family.right, jobs.category.wrong + jobs.family.wrong
    setting = "no thinking switch sent" if thinking else "thinking off"
    return (
        f"{head} (eval-local, {setting}): the judge {jobs.judge}/{judge.cases} in a run against {judge.default}/"
        f"{judge.cases} with no model; route {route_right} right and {route_wrong} wrong where a run asks it (its "
        f"category guesses {jobs.category.right} and {jobs.category.wrong} of {category.asked}, its family "
        f"{jobs.family.right} and {jobs.family.wrong} of {family.cases}); recon {jobs.recon.right} briefs right and "
        f"{jobs.recon.wrong} wrong of {recon.cases}; flagcheck {jobs.flagcheck}/{flagcheck.cases} in a run against "
        f"{flagcheck.default}/{flagcheck.cases} with the planted-flag hold alone; hint {jobs.hint}/{hint.cases} against "
        f"the rules' {hint.default}/{hint.cases}, which a run uses"
    )


def jobs_data(jobs: JobResults, offered: tuple[str, ...]) -> dict:
    """A build's jobs table as `flightdeck models --json` gives it: each job's figures beside
    flightdeck's default, and whether it is offered for each run job."""
    cases = jobs.cases

    def counted(key: str, of: int) -> dict:
        found = getattr(jobs, key)
        return {"right": found.right, "wrong": found.wrong, "of": of}

    return {
        JUDGE: {"right_in_a_run": jobs.judge, "cases": cases["judge"].cases, "no_model": cases["judge"].default,
                "offered": JUDGE in offered},
        ROUTE: {"category": {**counted("category", cases["category"].asked), "right_in_a_run":
                             cases["category"].default + jobs.category.right, "cases": cases["category"].cases,
                             "no_model": cases["category"].default},
                "family": counted("family", cases["family"].cases), "offered": ROUTE in offered},
        RECON: {**counted("recon", cases["recon"].cases), "offered": RECON in offered},
        FLAGCHECK: {"right_in_a_run": jobs.flagcheck, "cases": cases["flagcheck"].cases,
                    "no_model": cases["flagcheck"].default, "offered": FLAGCHECK in offered},
        "hint": {"right": jobs.hint, "cases": cases["hint"].cases, "rules": cases["hint"].default},
    }


def _api(entry: object, where: str) -> ApiChoice:
    entry, name = _named(entry, where, _API_KEYS, _API_REQUIRED)
    provider = entry["provider"]
    if provider not in PROVIDERS:
        raise CatalogError(f"{name}: provider must be one of {', '.join(PROVIDERS)}")
    if not isinstance(entry["classifier"], bool):
        raise CatalogError(f"{name}: classifier must be true or false")
    page = entry.get("models_page", "")
    if page and (not isinstance(page, str) or not page.startswith("https://")):
        raise CatalogError(f"{name}: models_page must be an https:// address")
    if provider == "openrouter" and not page:
        raise CatalogError(f"{name}: the openrouter entry names no models, so it needs models_page")
    return ApiChoice(
        id=entry["id"], name=_text(entry, "name", name), provider=provider, roles=_roles(entry, name),
        classifier=entry["classifier"], note=_text(entry, "note", name), models_page=page, **_provider(provider, name),
    )


def _provider(provider: str, name: str) -> dict:
    """The endpoint, ladder and prices `flightdeck init` writes for the provider (setup.py),
    imported so the catalog never holds a copy of them."""
    from .setup import ANTHROPIC, ANTHROPIC_LADDER, ANTHROPIC_PRICES, LIGHT_ANTHROPIC, anthropic_prices
    from .setup import PROVIDERS as INIT_PROVIDERS

    if provider == "anthropic":
        unpriced = [m for m in (*ANTHROPIC_LADDER, LIGHT_ANTHROPIC) if m not in ANTHROPIC_PRICES]
        if not ANTHROPIC_LADDER or unpriced:
            raise CatalogError(f"{name}: init's Anthropic ladder has no price for {', '.join(unpriced) or 'any model'}")
        # init's [prices] (the ladder's and its refusal fallback's models), and the light model's
        prices = {**anthropic_prices(ANTHROPIC_LADDER), LIGHT_ANTHROPIC: ANTHROPIC_PRICES[LIGHT_ANTHROPIC]}
        return {"base_url": ANTHROPIC[0], "key_env": ANTHROPIC[1], "ladder": tuple(ANTHROPIC_LADDER),
                "prices": MappingProxyType(prices), "light_model": LIGHT_ANTHROPIC}
    url, key_env = INIT_PROVIDERS["openrouter"]
    return {"base_url": url, "key_env": key_env, "ladder": (), "prices": MappingProxyType({}), "light_model": ""}


# ---------------------------------------------------------------------- what fits this machine


@dataclass(frozen=True)
class Budget:
    """What this machine gives local models: where they would run, how much memory, and why."""

    where: str  # APPLE, NVIDIA, CPU or UNKNOWN
    bytes: int | None  # None: cannot tell (why says why)
    why: str


def here(machine: Machine) -> str:
    """How the advice names where the machine is: "here", or "there" for a machine the player
    described instead of this one (hardware.described())."""
    return "there" if machine.described else "here"


def this(machine: Machine) -> str:
    """"this machine", or "the machine described" (hardware.described())."""
    return "the machine described" if machine.described else "this machine"


def budget(machine: Machine) -> Budget:
    """The memory local models may use here (see the module doc for the rule)."""
    from .text import untrusted

    memory = machine.memory.value
    if machine.apple_silicon.value:
        if memory is None:
            return Budget(UNKNOWN, None, f"this Mac's memory is unknown: {machine.memory.unknown}")
        share = memory * APPLE_SHARE[0] // APPLE_SHARE[1]
        return Budget(APPLE, share, (
            f"two thirds of the {gib(memory)} of unified memory. The GPU shares it with macOS, the Docker lanes and your "
            "other apps, and macOS lets the GPU use only part of it by default"))
    gpus = machine.gpus.value
    if gpus:
        best = max(gpus, key=lambda g: g.memory)
        many = f", the largest of the {len(gpus)} NVIDIA GPUs here (runtimes can also split a model across them)" if len(gpus) > 1 else ""
        return Budget(NVIDIA, best.memory, f"the memory of the {untrusted(best.name, one_line=True)}{many}")
    if gpus is None:
        return Budget(UNKNOWN, None, f"whether local models would run on an NVIDIA GPU is unknown: {machine.gpus.unknown}")
    if machine.os == "macOS" and machine.apple_silicon.value is None:
        return Budget(UNKNOWN, None, f"whether this Mac has Apple Silicon is unknown: {machine.apple_silicon.unknown}")
    if memory is None:
        return Budget(UNKNOWN, None, f"this machine's memory is unknown: {machine.memory.unknown}")
    share = memory * CPU_SHARE[0] // CPU_SHARE[1]
    looked = "none was described" if machine.described else "it looks for Apple Silicon and NVIDIA GPUs"
    return Budget(CPU, share, (
        f"half of the {gib(memory)} of memory, leaving the rest to the system and the Docker lanes. With no GPU flightdeck "
        f"can use ({looked}), local models run on the CPU and will be slow"))


@dataclass(frozen=True)
class Option:
    """One local model on one runtime, for one role, on this machine."""

    model: LocalModel
    build: Build
    role: str
    verdict: str  # FITS, TOO_BIG, CANNOT_TELL or NOT_HERE
    need: int | None  # bytes, estimated: size + the role's CONTEXT_ALLOWANCE; None with no size
    why: str
    present: bool  # its runtime's server here lists it now
    size: int | None = None  # bytes of weights the estimate used: the catalog's, else the server's here
    sized_by: str = ""  # SIZE_CATALOG, SIZE_SERVER, or "" with no size

    @property
    def measured(self) -> str:
        """This build's measured result for the role ("" until docs/MODELS.md has one)."""
        return self.build.measured.get(self.role, "")


@dataclass(frozen=True)
class Sizing:
    """A build's weights on this machine: the size the estimate uses, where it came from, and
    whether its runtime's server here lists it now."""

    size: int | None  # bytes; None: neither the catalog nor a server here gives one
    sized_by: str  # SIZE_CATALOG, SIZE_SERVER, or "" with no size
    present: bool


def sizing(build: Build, machine: Machine) -> Sizing:
    """The catalog's size for `build`; for a build the catalog has no size for, the one its
    server here gives it (Ollama, once pulled)."""
    runtime = machine.runtime(build.runtime)
    server = runtime.server if runtime is not None else None
    present = bool(server and server.lists(build.model))
    if build.size is not None:
        return Sizing(build.size, SIZE_CATALOG, present)
    size = server.size(build.model) if server is not None else None
    return Sizing(size, SIZE_SERVER if size is not None else "", present)


def judge(model: LocalModel, build: Build, role: str, machine: Machine, plan: Budget) -> Option:
    """Whether `build` fits this machine for `role`, and why (its size: sizing())."""
    if role not in model.serves(build):
        raise ValueError(f"{model.id} on {RUNTIME_NAMES[build.runtime]} does not serve {role}")
    found = sizing(build, machine)
    size, sized_by, present = found.size, found.sized_by, found.present
    need = None if size is None else size + CONTEXT_ALLOWANCE[role]

    def option(verdict: str, why: str) -> Option:
        return Option(model, build, role, verdict, need, why, present, size, sized_by)

    if build.runtime == MLX and not machine.apple_silicon.value:
        if machine.os == "macOS" and machine.apple_silicon.value is None:
            return option(CANNOT_TELL, f"MLX runs on Apple Silicon only, and {machine.apple_silicon.unknown}")
        return option(NOT_HERE, "MLX runs on Apple Silicon only")
    if size is None:
        pulled = build.runtime == OLLAMA and not machine.described  # a described machine's servers are not asked
        pull = f", and {RUNTIME_NAMES[OLLAMA]} here has not pulled it" if pulled else ""
        return option(CANNOT_TELL, f"its size on disk is not recorded in the catalog{pull}")
    source = f", as {RUNTIME_NAMES[build.runtime]} here gives them" if sized_by == SIZE_SERVER else ""
    parts = f"{gib(size)} of weights{source} + {gib(CONTEXT_ALLOWANCE[role])} for the context"
    if plan.bytes is None:
        return option(CANNOT_TELL, f"it needs about {gib(need)} ({parts}), and {plan.why}")
    if need <= plan.bytes:
        return option(FITS, f"needs about {gib(need)} ({parts}) of the {gib(plan.bytes)} {here(machine)}")
    return option(TOO_BIG, f"needs about {gib(need)} ({parts}), more than the {gib(plan.bytes)} {here(machine)}")


@dataclass(frozen=True)
class NotFor:
    """A local model, or one build of it, the catalog does not offer for a role, and why."""

    model: LocalModel
    build: Build | None  # None: the whole model (the role is not among its roles)
    why: str


ROLE_WORDS = {LANES: "lanes", LIGHT: "the light role"}  # "the catalog lists it for the light role only"


@dataclass(frozen=True)
class Advice:
    """One role's recommendations on this machine."""

    role: str
    where: str  # where local models would run: the budget's APPLE, NVIDIA, CPU or UNKNOWN
    lead: str  # LOCAL, API or RULES: what comes first
    lead_why: str  # a sentence: why it comes first
    fits: tuple[Option, ...]  # measured first; on the CPU, the smallest first
    too_big: tuple[Option, ...]
    cannot_tell: tuple[Option, ...]
    not_here: tuple[Option, ...]
    api: tuple[ApiChoice, ...]
    not_for: tuple[NotFor, ...] = ()  # in catalog order: never judged for this role


def not_for(catalog: Catalog, role: str) -> tuple[NotFor, ...]:
    """The local models, and builds, the catalog does not offer for `role`, with the reason."""
    out = []
    for model in catalog.local:
        if role not in model.roles:
            out.append(NotFor(model, None, f"the catalog lists it for {' and '.join(ROLE_WORDS[r] for r in model.roles)} only"))
            continue
        out += [NotFor(model, build, build.not_for[role]) for build in model.builds if role in build.not_for]
    return tuple(out)


def advise(catalog: Catalog, machine: Machine, role: str, plan: Budget | None = None) -> Advice:
    """The catalog's choices for `role` on this machine: local ones that fit first where local
    models run well (Apple Silicon, an NVIDIA GPU), else an API for lanes and the rules (or a
    small model) for the light role. A build the catalog says is not for the role is never
    offered for it (Advice.not_for)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}, not {role!r}")
    plan = plan if plan is not None else budget(machine)
    options = [judge(m, b, role, machine, plan) for m in catalog.local for b in m.builds if role in m.serves(b)]
    fits = [o for o in options if o.verdict == FITS]
    if plan.where == CPU:  # slow either way: the smallest first
        fits.sort(key=lambda o: (not o.measured, o.need))
    else:
        fits.sort(key=lambda o: not o.measured)  # stable: catalog order within each group
    if fits and plan.where in (APPLE, NVIDIA):
        lead, why = LOCAL, "No provider's safety classifier stands between it and security work, and it costs nothing."
    else:
        if plan.where == CPU:
            why = f"Local models would run on the CPU {here(machine)}, and slowly."
        elif plan.where == UNKNOWN:
            why = f"flightdeck cannot tell what fits {this(machine)}."
        else:  # a model that is not for the role may fit by size: it is not counted
            why = f"No model the catalog offers for {ROLE_WORDS[role]} is known to fit {this(machine)}."
        lead = RULES if role == LIGHT else API
    return Advice(
        role=role, where=plan.where, lead=lead, lead_why=why, fits=tuple(fits),
        too_big=tuple(o for o in options if o.verdict == TOO_BIG),
        cannot_tell=tuple(o for o in options if o.verdict == CANNOT_TELL),
        not_here=tuple(o for o in options if o.verdict == NOT_HERE),
        api=tuple(a for a in catalog.api if role in a.roles),
        not_for=not_for(catalog, role),
    )


# ---------------------------------------------------------------------- getting one, and its config lines


OLLAMA_DOWNLOAD = "https://ollama.com/download"
KEEP_ARGS = "# keep the arguments after --port 8080: the benchmark behind {doc} served it with them"


def serve_command(build: Build) -> str:
    """The mlx_lm.server command that serves `build` on 127.0.0.1 (MLX_URL's port), with its server_args."""
    return shlex.join(["mlx_lm.server", "--model", build.model, "--host", "127.0.0.1", "--port", "8080", *build.server_args])


def get_commands(build: Build, machine: Machine | None = None) -> list[str]:
    """The commands that get `build` and serve it on this machine: first how to install its
    runtime, when `machine` shows its program is not on PATH (the commands below need it)."""
    runtime = machine.runtime(build.runtime) if machine is not None else None
    missing = runtime is not None and runtime.program is None
    if build.runtime == OLLAMA:
        install = [f"# Ollama is not on PATH: install it first ({OLLAMA_DOWNLOAD})"] if missing else []
        return [*install, f"ollama pull {shlex.quote(build.model)}"]
    install = ["uv tool install mlx-lm   # puts mlx_lm.server on PATH (or: pip install mlx-lm)"] if missing else []
    keep = [KEEP_ARGS.format(doc=MODELS_DOC)] if build.server_args else []
    return [*install, serve_command(build), *keep]


def measure_command(build: Build, role: str) -> str:
    """How to try `build` in `role` before relying on it: for the light role, eval-local with the
    [light] thinking its results were measured with."""
    if role == LIGHT:
        thinking = " --thinking on" if build.thinking else ""
        return (f"flightdeck eval-local --engine openai --base-url {SERVER_URLS[build.runtime]} --model "
                f"{shlex.quote(build.model)}{thinking}")
    return "flightdeck practice   # the practice set, on the ladder above"


def _toml(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


NO_KEY = '   # a server on this machine needs no key'


THINKING_ON = ("   # as its results were measured: no thinking switch sent (flightdeck's default here, thinking off, "
               "was not measured)")
JOBS_MEASURED = "   # the jobs it did no worse at than flightdeck's default (`flightdeck models` gives each job's score)"
JOBS_EARLIER = "   # the one job a run gives it that was measured; route, recon and flagcheck were not"


def local_lines(build: Build, role: str) -> str:
    """The config lines that use `build` in `role`: [api] and [models] for lanes, [light] for the
    light role, with the [light] thinking its results were measured with when that is not the
    default, and the jobs it is offered for (light_jobs)."""
    url = SERVER_URLS[build.runtime]
    if role == LANES:
        return (
            "[api]\n"
            f"base_url = {_toml(url)}\n"
            f'key_env = ""{NO_KEY}\n'
            "\n"
            "[models]\n"
            f"ladder = [{_toml(build.model)}]   # weakest first: stronger models this server has go after it\n"
            "\n"
            "# and under [lanes]: dollar_cap = false   (a model on this machine reports no cost)\n"
        )
    out = (
        "[light]\n"
        'engine = "openai"\n'
        f"model = {_toml(build.model)}\n"
        f"base_url = {_toml(url)}\n"
        f'key_env = ""{NO_KEY}\n'
    )
    if build.thinking is not None:
        out += f"thinking = {'true' if build.thinking else 'false'}{THINKING_ON if build.thinking else ''}\n"
    if build.light_jobs:
        out += f"jobs = [{', '.join(_toml(job) for job in build.light_jobs)}]{JOBS_MEASURED if build.jobs else JOBS_EARLIER}\n"
    return out


PLACEHOLDER_LADDER = ("VENDOR/SMALL-MODEL", "VENDOR/BIG-MODEL")
PLACEHOLDER_MODEL = "VENDOR/MODEL"


def api_lines(api: ApiChoice, role: str) -> str:
    """The config lines that use `api` in `role`. For an API whose models the player chooses
    (OpenRouter), the model ids are placeholders in capitals, to replace from its models page."""
    if role == LANES:
        ladder = api.ladder or PLACEHOLDER_LADDER
        out = "[api]\n"
        if api.provider == "anthropic":
            out += 'provider = "anthropic"   # the Anthropic Messages API\n'
        out += (
            f"base_url = {_toml(api.base_url)}\n"
            f"key_env = {_toml(api.key_env)}   # the variable that holds your key (never the key)\n"
            "\n"
            "[models]\n"
            f"ladder = [{', '.join(_toml(m) for m in ladder)}]   # weakest first; "
            f"{'ids from ' + api.models_page if api.models_page and not api.ladder else 'escalation climbs it'}\n"
        )
        from .agent.refusal import answering
        from .setup import price_lines

        for model in (*api.ladder, *answering(api.ladder)):  # the refusal fallback's models too, as init writes them
            price = api.prices.get(model)
            if price is not None:
                out += f"\n[prices.{_toml(model)}]\n" + price_lines(price)
        return out
    model = api.light_model or PLACEHOLDER_MODEL
    engine = "anthropic" if api.provider == "anthropic" else "openai"
    out = (
        "[light]\n"
        f"engine = {_toml(engine)}\n"
        f"model = {_toml(model)}{'' if api.light_model else f'   # an id from {api.models_page}'}\n"
        f"base_url = {_toml(api.base_url)}\n"
        f"key_env = {_toml(api.key_env)}\n"
    )
    price = api.prices.get(model)
    if price is not None:
        from .setup import price_table

        out += f"price = {price_table(price)}   # dollars per million tokens\n"
    return out


def init_command(choice: LocalModel | ApiChoice, role: str, build: Build | None = None) -> str:
    """The `flightdeck init` that writes a whole new config with this choice ("" when none does:
    init writes a light model on this machine with thinking off, so not one measured with it on)."""
    if isinstance(choice, ApiChoice):
        if choice.provider == "anthropic":
            return "flightdeck init --provider anthropic" if role == LANES else "flightdeck init --light anthropic"
        return ""
    assert build is not None
    model = shlex.quote(build.model)
    if role == LANES:
        return f"flightdeck init --provider {'local' if build.runtime == OLLAMA else 'mlx'} --models {model}"
    if build.thinking:
        return ""
    return f"flightdeck init --light {build.runtime} --light-model {model}"
