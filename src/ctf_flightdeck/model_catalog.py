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

from .config import MLX_URL, OLLAMA_URL
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

_LOCAL_KEYS = ("id", "name", "family", "parameters", "license", "roles", "measured", *BUILDS)
_LOCAL_REQUIRED = ("id", "name", "family", "parameters", "license", "roles", "measured")
_BUILD_KEYS = ("model", "quantization", "size_bytes")
_API_KEYS = ("id", "name", "provider", "roles", "classifier", "note", "models_page")
_API_REQUIRED = ("id", "name", "provider", "roles", "classifier", "note")
_ID = re.compile(r"[a-z0-9][a-z0-9.-]*")
_PARAMETERS = re.compile(r"[0-9]+(?:\.[0-9]+)?[MB]")


class CatalogError(ValueError):
    """The catalog cannot be used; the message names the file and the entry."""


@dataclass(frozen=True)
class Build:
    """A local model as one runtime serves it."""

    runtime: str  # OLLAMA or MLX
    model: str  # the runtime's name for it: an Ollama tag, a Hugging Face repo for mlx_lm.server
    quantization: str | None = None  # None: not recorded
    size: int | None = None  # bytes of its weights on disk; None: not recorded


@dataclass(frozen=True)
class LocalModel:
    id: str
    name: str
    family: str
    parameters: str  # "9.0B"
    license: str
    roles: tuple[str, ...]
    measured: Mapping[str, str]  # role -> a one-line result from docs/MODELS.md
    builds: tuple[Build, ...]

    def build(self, runtime: str) -> Build | None:
        return next((b for b in self.builds if b.runtime == runtime), None)


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
    prices: Mapping[str, Price]  # dollars per million tokens, per ladder model
    light_model: str  # the model `init --light` writes for it; "" when the player chooses


@dataclass(frozen=True)
class Catalog:
    local: tuple[LocalModel, ...]
    api: tuple[ApiChoice, ...]

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
    extra = [key for key in data if key not in ("local", "api")]
    if extra:
        raise CatalogError(f"{where}: unknown top-level key {', '.join(extra)} (known: local, api)")
    local_entries, api_entries = data.get("local", []), data.get("api", [])
    for table, entries in (("local", local_entries), ("api", api_entries)):
        if not isinstance(entries, list):
            raise CatalogError(f"{where}: {table} must be a list of [[{table}]] tables")
    if not local_entries:
        raise CatalogError(f"{where} has no [[local]] entries")
    local = tuple(_local(entry, f"{where}: [[local]] entry {n}") for n, entry in enumerate(local_entries, 1))
    api = tuple(_api(entry, f"{where}: [[api]] entry {n}") for n, entry in enumerate(api_entries, 1))
    seen: dict[str, str] = {}
    for kind, entries in (("local", local), ("api", api)):
        for n, entry in enumerate(entries, 1):
            here = f"[[{kind}]] entry {n}"
            if entry.id in seen:
                raise CatalogError(f"{where}: id {entry.id!r} is used twice: by {seen[entry.id]} and {here}")
            seen[entry.id] = here
    return Catalog(local, api)


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


def _local(entry: object, where: str) -> LocalModel:
    entry, name = _named(entry, where, _LOCAL_KEYS, _LOCAL_REQUIRED)
    roles = _roles(entry, name)
    parameters = _text(entry, "parameters", name)
    if not _PARAMETERS.fullmatch(parameters):
        raise CatalogError(f"{name}: parameters must be a count like 9.0B or 750M")
    measured = entry["measured"]
    if not isinstance(measured, dict):
        raise CatalogError(f"{name}: measured must be a table of role = \"result\" (empty until measured)")
    for role, result in measured.items():
        if role not in roles:
            raise CatalogError(f"{name}: measured.{role} is not one of its roles ({', '.join(roles)})")
        if not isinstance(result, str) or not result.strip() or not result.isprintable():
            raise CatalogError(f"{name}: measured.{role} must be a one-line result")
    builds = tuple(_build(entry[runtime], runtime, name) for runtime in BUILDS if runtime in entry)
    if not builds:
        raise CatalogError(f"{name}: names no runtime: add [local.ollama] or [local.mlx]")
    return LocalModel(
        id=entry["id"], name=_text(entry, "name", name), family=_text(entry, "family", name), parameters=parameters,
        license=_text(entry, "license", name), roles=roles, measured=MappingProxyType(dict(measured)), builds=builds,
    )


def _build(table: object, runtime: str, name: str) -> Build:
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
    return Build(runtime, model, quantization, size)


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
    from .setup import ANTHROPIC, ANTHROPIC_LADDER, ANTHROPIC_PRICES, LIGHT_ANTHROPIC, PROVIDERS as INIT_PROVIDERS

    if provider == "anthropic":
        unpriced = [m for m in (*ANTHROPIC_LADDER, LIGHT_ANTHROPIC) if m not in ANTHROPIC_PRICES]
        if not ANTHROPIC_LADDER or unpriced:
            raise CatalogError(f"{name}: init's Anthropic ladder has no price for {', '.join(unpriced) or 'any model'}")
        prices = {m: ANTHROPIC_PRICES[m] for m in dict.fromkeys((*ANTHROPIC_LADDER, LIGHT_ANTHROPIC))}
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
    return Budget(CPU, share, (
        f"half of the {gib(memory)} of memory, leaving the rest to the system and the Docker lanes. With no GPU flightdeck "
        "can use (it looks for Apple Silicon and NVIDIA GPUs), local models run on the CPU and will be slow"))


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
        return self.model.measured.get(self.role, "")


def judge(model: LocalModel, build: Build, role: str, machine: Machine, plan: Budget) -> Option:
    """Whether `build` fits this machine for `role`, and why. Its size is the catalog's; for a
    build the catalog has no size for, the one its server here gives it (Ollama, once pulled)."""
    runtime = machine.runtime(build.runtime)
    server = runtime.server if runtime is not None else None
    present = bool(server and server.lists(build.model))
    size, sized_by = build.size, SIZE_CATALOG
    if size is None and server is not None:
        size, sized_by = server.size(build.model), SIZE_SERVER
    if size is None:
        sized_by = ""
    need = None if size is None else size + CONTEXT_ALLOWANCE[role]

    def option(verdict: str, why: str) -> Option:
        return Option(model, build, role, verdict, need, why, present, size, sized_by)

    if build.runtime == MLX and not machine.apple_silicon.value:
        if machine.os == "macOS" and machine.apple_silicon.value is None:
            return option(CANNOT_TELL, f"MLX runs on Apple Silicon only, and {machine.apple_silicon.unknown}")
        return option(NOT_HERE, "MLX runs on Apple Silicon only")
    if size is None:
        pull = f", and {RUNTIME_NAMES[OLLAMA]} here has not pulled it" if build.runtime == OLLAMA else ""
        return option(CANNOT_TELL, f"its size on disk is not recorded in the catalog{pull}")
    source = f", as {RUNTIME_NAMES[build.runtime]} here gives them" if sized_by == SIZE_SERVER else ""
    parts = f"{gib(size)} of weights{source} + {gib(CONTEXT_ALLOWANCE[role])} for the context"
    if plan.bytes is None:
        return option(CANNOT_TELL, f"it needs about {gib(need)} ({parts}), and {plan.why}")
    if need <= plan.bytes:
        return option(FITS, f"needs about {gib(need)} ({parts}) of the {gib(plan.bytes)} here")
    return option(TOO_BIG, f"needs about {gib(need)} ({parts}), more than the {gib(plan.bytes)} here")


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


def advise(catalog: Catalog, machine: Machine, role: str, plan: Budget | None = None) -> Advice:
    """The catalog's choices for `role` on this machine: local ones that fit first where local
    models run well (Apple Silicon, an NVIDIA GPU), else an API for lanes and the rules (or a
    small model) for the light role."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}, not {role!r}")
    plan = plan if plan is not None else budget(machine)
    options = [judge(m, b, role, machine, plan) for m in catalog.local if role in m.roles for b in m.builds]
    fits = [o for o in options if o.verdict == FITS]
    if plan.where == CPU:  # slow either way: the smallest first
        fits.sort(key=lambda o: (not o.measured, o.need))
    else:
        fits.sort(key=lambda o: not o.measured)  # stable: catalog order within each group
    if fits and plan.where in (APPLE, NVIDIA):
        lead, why = LOCAL, "No provider's safety classifier stands between it and security work, and it costs nothing."
    else:
        if plan.where == CPU:
            why = "Local models would run on the CPU here, and slowly."
        elif plan.where == UNKNOWN:
            why = "flightdeck cannot tell what fits this machine."
        else:
            why = "No catalog model with a recorded size fits this machine."
        lead = RULES if role == LIGHT else API
    return Advice(
        role=role, where=plan.where, lead=lead, lead_why=why, fits=tuple(fits),
        too_big=tuple(o for o in options if o.verdict == TOO_BIG),
        cannot_tell=tuple(o for o in options if o.verdict == CANNOT_TELL),
        not_here=tuple(o for o in options if o.verdict == NOT_HERE),
        api=tuple(a for a in catalog.api if role in a.roles),
    )


# ---------------------------------------------------------------------- getting one, and its config lines


OLLAMA_DOWNLOAD = "https://ollama.com/download"


def get_commands(build: Build, machine: Machine | None = None) -> list[str]:
    """The commands that get `build` and serve it on this machine: first how to install its
    runtime, when `machine` shows it is not installed."""
    model = shlex.quote(build.model)
    runtime = machine.runtime(build.runtime) if machine is not None else None
    missing = runtime is not None and not runtime.installed
    if build.runtime == OLLAMA:
        install = [f"# Ollama is not on PATH: install it first ({OLLAMA_DOWNLOAD})"] if missing else []
        return [*install, f"ollama pull {model}"]
    install = ["uv tool install mlx-lm   # mlx_lm.server comes with the mlx-lm package (or: pip install mlx-lm)"]
    return [*(install if missing else []), f"mlx_lm.server --model {model} --host 127.0.0.1 --port 8080"]


def measure_command(build: Build, role: str) -> str:
    """How to try `build` in `role` before relying on it."""
    if role == LIGHT:
        return f"flightdeck eval-local --engine openai --base-url {SERVER_URLS[build.runtime]} --model {shlex.quote(build.model)}"
    return "flightdeck practice   # the practice set, on the ladder above"


def _toml(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


NO_KEY = '   # a server on this machine needs no key'


def local_lines(build: Build, role: str) -> str:
    """The config lines that use `build` in `role`: [api] and [models] for lanes, [light] for the light role."""
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
    return (
        "[light]\n"
        'engine = "openai"\n'
        f"model = {_toml(build.model)}\n"
        f"base_url = {_toml(url)}\n"
        f'key_env = ""{NO_KEY}\n'
    )


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
        for model in api.ladder:
            price = api.prices.get(model)
            if price is not None:
                out += f"\n[prices.{_toml(model)}]\ninput = {price.input:g}\noutput = {price.output:g}\n"
                if price.cached_input is not None:
                    out += f"cached_input = {price.cached_input:g}\n"
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
        parts = [f"input = {price.input:g}", f"output = {price.output:g}"]
        if price.cached_input is not None:
            parts.append(f"cached_input = {price.cached_input:g}")
        out += "price = { " + ", ".join(parts) + " }   # dollars per million tokens\n"
    return out


def init_command(choice: LocalModel | ApiChoice, role: str, build: Build | None = None) -> str:
    """The `flightdeck init` that writes a whole new config with this choice ("" when none does)."""
    if isinstance(choice, ApiChoice):
        if choice.provider == "anthropic":
            return "flightdeck init --provider anthropic" if role == LANES else "flightdeck init --light anthropic"
        return ""
    assert build is not None
    model = shlex.quote(build.model)
    if role == LANES:
        return f"flightdeck init --provider {'local' if build.runtime == OLLAMA else 'mlx'} --models {model}"
    return f"flightdeck init --light {build.runtime} --light-model {model}"
