"""`flightdeck models`: which models fit this machine, and where flightdeck would use each.

cli.py mounts models_command onto the root CLI, in the "Set up" panel.

It looks at this machine (hardware.py: each probe with a short timeout, no root, nothing
contacted but 127.0.0.1), matches the model catalog against it (model_catalog.py, models.toml)
and prints, per role, the models that fit and why, those that do not and why, which were
measured (docs/MODELS.md) and which only fit by size, then the model APIs. `flightdeck models ID`
says how to get that model and the exact config lines that use it. --json prints the same as
JSON, for scripts.

--memory GB (with --apple for an Apple Silicon Mac, or --gpu-memory GB for an NVIDIA GPU)
describes another machine instead (hardware.described()): the same advice, from its memory and
GPU, said to be for the machine described; nothing here is probed for it, and what only this
machine can tell (its runtimes, the models they have pulled) is left out. There is no option for
CPU cores: speed follows memory bandwidth and the GPU, not the cores (and fits, the advice, follow
memory alone).

It recommends: it never picks for the player, and never writes or changes a config.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from typing import Annotated

import typer

from . import hardware, model_catalog
from .hardware import DOWN, GIB, LLAMA_CPP, LM_STUDIO, MLX, OLLAMA, SERVING, Machine, Runtime, gib
from .model_catalog import (
    API,
    CONTEXT_ALLOWANCE,
    CPU,
    FITS,
    LANES,
    LIGHT,
    LOCAL,
    MODELS_DOC,
    ROLES,
    RULES,
    SIZE_SERVER,
    Advice,
    ApiChoice,
    Budget,
    Build,
    Catalog,
    CatalogError,
    LocalModel,
    NotFor,
    Option,
    advise,
    api_lines,
    budget,
    get_commands,
    init_command,
    jobs_data,
    judge,
    load_catalog,
    local_lines,
    measure_command,
    sizing,
)
from .text import untrusted

SHOWN_MODELS = 8  # model names a runtime line shows before "and N more"
ROLE_TITLES = {
    LANES: "Lanes: the tool loop, on [api] and the [models] ladder (weakest first; escalation climbs it). "
           "A lane needs reliable tool calls.",
    LIGHT: "Light role: [light], the small jobs a run gives a light model ([light] jobs: the hint judge, route, "
           "recon, flagcheck). The default is the rules, no model; a model is offered for the jobs it did no worse "
           "at than that. Measure one with `flightdeck eval-local` before you switch it on.",
}
APPROXIMATE = ("Every measured number is approximate: one run each, on one Mac (Apple M4 Max, 36 GB) under heavy "
               "load, 2026-11-11.")
ROLE_NAMES = {LANES: "a lane", LIGHT: "the light role"}  # "not measured for a lane yet"
ROLE_HEADS = {LANES: "lanes", LIGHT: "the light role"}  # "For lanes and the light role."
MEMORY_RULE = (
    f"A local model needs about its weights (its size on disk) plus room for its context: "
    f"{gib(CONTEXT_ALLOWANCE[LANES])} for a lane, whose context grows long over a tool loop, and "
    f"{gib(CONTEXT_ALLOWANCE[LIGHT])} for the light role, whose prompts are short. An estimate: the real need depends "
    "on the runtime, its context length and the model."
)
TABLES = {  # where a role's config lines go
    LANES: "in your config, these replace its [api], [models] and [prices] tables (keep a [fallback] table only with one "
           "model per ladder entry):",
    LIGHT: "in your config, these replace its [light] table and any [light.<job>] tables:",
}
RECOMMENDS = "This only recommends: it never changes your config."
AGENTS = ("Coding-agent lanes (`flightdeck play --agent claude` or `codex`) bring their own models: [agents] in your "
          "config, not this list.")


def this_machine() -> Machine:
    """This machine's facts: hardware.probe() on hardware.RealHost (a test swaps in a fake host)."""
    return hardware.probe()


MAX_GB = hardware.MAX_MEMORY // GIB  # the most memory a described machine may have, in GB (1 PiB)


def described_machine(memory: float | None, apple: bool, gpu_memory: float | None) -> Machine | None:
    """The machine --memory, --apple and --gpu-memory describe (memory in GB of 2^30 bytes, as a
    machine's spec gives it), or None when none of them is given: this machine, then.
    ValueError names the option and why it cannot be used."""
    if memory is None:
        if apple:
            raise ValueError("--apple says the memory --memory gives is unified, on Apple Silicon: give --memory GB too")
        if gpu_memory is not None:
            raise ValueError("--gpu-memory describes another machine's NVIDIA GPU: give that machine's memory with "
                             "--memory GB too")
        return None
    if not math.isfinite(memory) or not 0 < memory <= MAX_GB:
        raise ValueError(f"--memory must be the machine's memory in GB, above 0 and at most {MAX_GB:,} "
                         f"(got {memory:,.15g})")
    gpu = 0.0 if gpu_memory is None else gpu_memory
    if not math.isfinite(gpu) or not 0 <= gpu <= MAX_GB:
        raise ValueError(f"--gpu-memory must be an NVIDIA GPU's memory in GB, 0 for none, and at most {MAX_GB:,} "
                         f"(got {gpu:,.15g})")
    if apple and gpu:
        raise ValueError("an Apple Silicon Mac has no NVIDIA GPU: give --apple or --gpu-memory, not both")
    memory_bytes, gpu_bytes = round(memory * GIB), round(gpu * GIB)
    if not memory_bytes:
        raise ValueError(f"--memory must be the machine's memory in GB, above 0 (got {memory:,.15g})")
    return hardware.described(memory_bytes, apple=apple, gpu=gpu_bytes)


def described_flags(machine: Machine) -> str:
    """The options that describe `machine` again ("" for this machine), for the commands it suggests."""
    if not machine.described:
        return ""
    flags = f" --memory {machine.memory.value / GIB:g}"
    if machine.apple_silicon.value:
        flags += " --apple"
    if machine.gpus.value:
        flags += f" --gpu-memory {machine.gpus.value[0].memory / GIB:g}"
    return flags


def models_command(
    entry: Annotated[
        str | None,
        typer.Argument(metavar="ID", show_default=False,
                       help="A model from the list: how to get it, and the config lines that use it."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", metavar="", help="Print the same as JSON, for scripts.")] = False,
    memory: Annotated[float | None, typer.Option(
        "--memory", metavar="GB", show_default=False,
        help="Advise for another machine instead of this one: its memory (RAM) in GB, as its spec gives it.")] = None,
    apple: Annotated[bool, typer.Option(
        "--apple", metavar="", help="With --memory: the machine is an Apple Silicon Mac, whose memory is unified (the GPU shares "
                        "it).")] = False,
    gpu_memory: Annotated[float | None, typer.Option(
        "--gpu-memory", metavar="GB", show_default=False,
        help="With --memory: the memory of its NVIDIA GPU, in GB (0 or left out: none).")] = None,
) -> None:
    """Which models fit this machine (or one --memory describes), and where flightdeck would use
    each: local open-weight models first, then model APIs. It recommends; it never changes your
    config."""
    try:
        described = described_machine(memory, apple, gpu_memory)
    except ValueError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    try:
        catalog = load_catalog()
    except CatalogError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    if entry is None:
        machine = described or this_machine()
        if as_json:
            typer.echo(json.dumps(overview_json(catalog, machine), indent=2))
        else:
            typer.echo(overview_text(catalog, machine), nl=False)
        return
    choice = catalog.get(entry)
    if choice is None:
        typer.echo(f"flightdeck: no model {untrusted(entry, one_line=True)!r} in the catalog; it has "
                   f"{', '.join(catalog.ids)}", err=True)
        raise typer.Exit(2)
    machine = None if isinstance(choice, ApiChoice) else (described or this_machine())  # an API: nothing to look at
    if as_json:
        typer.echo(json.dumps(entry_json(choice, machine), indent=2))
    else:
        typer.echo(entry_text(choice, machine), nl=False)


# ---------------------------------------------------------------------- the overview


DESCRIBED = ("The machine described, not this one: the advice below is for it. What only this machine can tell, its "
             "model runtimes and the models they have pulled, is left out.")


def this_config():
    """The player's config, to see whether its lanes use Ollama: (config, ""), (None, "") when
    there is no config file, or (None, why) when it cannot be read. Read only, never written."""
    from .config import ConfigError, default_config_path, load_config

    try:
        path = default_config_path()
        if not path.exists():
            return None, ""
        return load_config(path), ""
    except ConfigError as exc:
        return None, str(exc)


@dataclass(frozen=True)
class LaneContext:
    """What `flightdeck models` says of the context Ollama gives lanes: the lines, and the same for --json."""

    lines: tuple[str, ...]
    data: dict


def lane_context(machine: Machine, advice: Advice, config_state: tuple) -> LaneContext | None:
    """The context Ollama gives a lane: for the lanes of the player's config when they use Ollama
    on this machine (ollama_context.lane_finding: what Ollama says of a loaded model, else an
    estimate), else Ollama's default on this machine or the one described, when an Ollama build
    fits lanes there. None when neither applies."""
    from .agent.driver import COMPACT_AT
    from .config import LOCAL_MAX_TOKENS, lane_refresh_at, reply_room
    from .light import on_this_machine
    from .ollama_context import default_contexts, default_note, default_port, lane_finding, ollama_root

    environ = {} if machine.described else os.environ
    estimate = default_contexts(machine, environ)
    config, unread = config_state if not machine.described else (None, "")
    api = config.api if config is not None else None
    if api is not None and api.provider == "openai" and on_this_machine(api.base_url) and default_port(api.base_url):
        runtime = machine.runtime(OLLAMA)
        server = runtime.server if runtime is not None else None
        loaded = server.loaded if server is not None else None
        finding = lane_finding(_safe(ollama_root(api.base_url).split("://", 1)[-1]), config.models, loaded, estimate,
                               lane_refresh_at(config, COMPACT_AT), reply_room(api.provider, api.base_url, api.max_tokens),
                               stated_context=api.context, source=str(config.source or ""))
        if finding is not None:
            lines = [f"  Your config's lanes: {finding.detail}."]
            if not finding.ok:
                lines.append(f"    fix: {finding.fix}")
            return LaneContext(tuple(lines), {"config": True, **finding.as_json()})
    ollama_fits = any(o.build.runtime == OLLAMA for o in advice.fits)
    if estimate is None or not ollama_fits:
        return None
    ok, note = default_note(estimate, COMPACT_AT, LOCAL_MAX_TOKENS, model_catalog.here(machine))
    lines = [f"  {note}"]
    if unread:
        lines.append(f"  Your config is not read here ({_safe(unread)}): `flightdeck doctor` says what is wrong with it.")
    return LaneContext(tuple(lines), {"config": False, "ok": ok, "tokens": list(estimate.tokens), "detail": note})


def overview_text(catalog: Catalog, machine: Machine) -> str:
    plan = budget(machine)
    head = ["The machine described", *described_lines(machine), "", DESCRIBED] if machine.described else [
        "This machine", *machine_lines(machine)]
    lines = [*head, "", f"{_budget_line(plan, machine)}.", MEMORY_RULE, APPROXIMATE]
    config_state = this_config() if not machine.described else (None, "")
    for role in ROLES:
        advice = advise(catalog, machine, role, plan)
        lines += ["", *role_lines(advice, machine)]
        if role == LANES:
            context = lane_context(machine, advice, config_state)
            lines += list(context.lines) if context is not None else []
    example = next((o.model.id for role in ROLES for o in advise(catalog, machine, role, plan).fits), catalog.local[0].id)
    flags = described_flags(machine)
    lines += [
        "",
        AGENTS,
        f"Measured results: {MODELS_DOC}. How to get a model and the config lines that use it: "
        f"flightdeck models ID{flags} (for example: flightdeck models {example}{flags}).",
        RECOMMENDS,
    ]
    return "\n".join(lines) + "\n"


def _budget_line(plan: Budget, machine: Machine) -> str:
    where = model_catalog.here(machine)
    if plan.bytes is None:
        return f"Local models: flightdeck cannot tell what fits {where}: {plan.why}"
    return f"Local models may use about {gib(plan.bytes)} {where}: {plan.why}"


def _said(machine: Machine) -> str:
    """A described machine in a few words: "36 GiB of unified memory, on Apple Silicon"."""
    memory = gib(machine.memory.value or 0)
    if machine.apple_silicon.value:
        return f"{memory} of unified memory, on Apple Silicon"
    gpus = machine.gpus.value
    return f"{memory} of memory, " + (f"an NVIDIA GPU with {gib(gpus[0].memory)}" if gpus else "no NVIDIA GPU")


def described_lines(machine: Machine) -> list[str]:
    """A described machine's facts, a line each: what the player gave, and nothing probed."""
    memory = gib(machine.memory.value or 0)
    if machine.apple_silicon.value:
        rows = [("system", "an Apple Silicon Mac (--apple)"), ("memory", f"{memory}, unified: the CPU and GPU share it")]
    else:
        gpus = machine.gpus.value
        rows = [("memory", memory),
                ("NVIDIA GPU", f"one, with {gib(gpus[0].memory)} (--gpu-memory)" if gpus else "none described")]
    width = max(len(name) for name, _ in rows)
    return [f"  {name:<{width}}  {text}" for name, text in rows]


def machine_lines(machine: Machine) -> list[str]:
    """This machine's facts, a line each."""
    if machine.os == "macOS":
        system = f"macOS on {machine.arch}"
        if machine.chip.value:
            system += f": {_safe(machine.chip.value)}"
        elif machine.chip.unknown:
            system += f": chip unknown ({machine.chip.unknown})"
        if machine.apple_silicon.value:
            system += " (Apple Silicon)"
        elif machine.apple_silicon.value is None:
            system += f"; Apple Silicon unknown ({machine.apple_silicon.unknown})"
    else:
        wsl = " (WSL)" if machine.wsl.value else ""
        system = f"{machine.os}{wsl} on {machine.arch}"
    if machine.memory.value is not None:
        memory = gib(machine.memory.value)
        if machine.apple_silicon.value:
            memory += ", unified: the CPU and GPU share it"
        if machine.wsl.value:
            memory += ", what WSL's virtual machine has (.wslconfig sets it)"
    else:
        memory = f"unknown: {machine.memory.unknown}"
    if machine.gpus.value:
        gpus = "; ".join(f"{_safe(g.name)}, {gib(g.memory)}" for g in machine.gpus.value)
    elif machine.gpus.value is None:
        gpus = f"unknown: {machine.gpus.unknown}"
    else:
        gpus = f"none found: {machine.gpu_note}"
    rows = [("system", system), ("memory", memory), ("NVIDIA GPU", gpus)]
    rows += [(runtime.label, runtime_line(runtime)) for runtime in machine.runtimes]
    width = max(len(name) for name, _ in rows)
    return [f"  {name:<{width}}  {text}" for name, text in rows]


def runtime_line(runtime: Runtime) -> str:
    parts = []
    if runtime.program_name:
        if runtime.program:
            parts.append(f"{runtime.program_name} at {_safe(runtime.program)}")
        else:
            parts.append(f"{runtime.program_name} is not on PATH")
    if runtime.name == MLX and runtime.importable:
        parts.append("the mlx_lm package is installed")
    if runtime.name == LLAMA_CPP and runtime.program:
        parts.append("its server's default port is 8080, as an MLX server's")
    server = runtime.server
    if server is not None:
        if server.state == SERVING:
            what = {OLLAMA: "its server at {} has pulled", LM_STUDIO: "its server at {} lists"}.get(
                runtime.name, "a server at {} lists").format(server.address)
            parts.append(f"{what} {_models(server.models)}")
            if server.loaded:
                parts.append("it has loaded " + ", ".join(f"{_safe(name)} with {tokens:,} tokens of context"
                                                          for name, tokens in server.loaded.items()))
            elif server.loaded_why:
                parts.append(f"which models it has loaded is unknown ({server.loaded_why})")
        elif server.state == DOWN:
            parts.append(f"nothing is listening at {server.address}")
        else:
            parts.append(f"at {server.address}: unknown ({server.why})")
    return "; ".join(parts)


def _models(names: tuple[str, ...]) -> str:
    if not names:
        return "no models"
    shown = ", ".join(_safe(name) for name in names[:SHOWN_MODELS])
    more = f" and {len(names) - SHOWN_MODELS} more" if len(names) > SHOWN_MODELS else ""
    return f"{len(names)} model{'s' if len(names) != 1 else ''}: {shown}{more}"


def role_lines(advice: Advice, machine: Machine | None = None) -> list[str]:
    """One role's section: what comes first and why, the local models (fit, too big, cannot
    tell, not for this machine, not for this role) and the model APIs, in the order the advice
    leads with. A described machine (hardware.described()) is "there", never "here"."""
    role = advice.role
    there = machine is not None and machine.described
    where = "there" if there else "here"
    lines = [ROLE_TITLES[role], f"  First: {_lead(advice, there)}"]
    fits = [f"    {_option_line(o)}" for o in advice.fits]
    fit_here = f"  Fit {where}, on the CPU (slow):" if advice.where == CPU else f"  Fit {where}:"
    api = [f"    {_api_line(a, role)}" for a in advice.api]
    if advice.lead == API:
        lines += ["  Model APIs:", *api]
        if fits:
            lines += [fit_here, *fits]
    else:
        if advice.lead == RULES:
            lines.append("    rules: the default; no model, no cost")
        if fits:
            lines += [fit_here, *fits]
        lines += ["  Model APIs:", *api]
    if advice.too_big:
        lines += [f"  Do not fit {where}:", *(f"    {_option_line(o)}" for o in advice.too_big)]
    if advice.cannot_tell:
        lines += ["  Cannot tell:", *(f"    {_option_line(o)}" for o in advice.cannot_tell)]
    if advice.not_here:
        named = ", ".join(f"{o.model.id} on {_runtime_label(o.build.runtime)}" for o in advice.not_here)
        why = "; ".join(dict.fromkeys(o.why for o in advice.not_here))
        lines.append(f"  Not for {'that' if there else 'this'} machine: {named} ({why})")
    if advice.not_for:
        lines += [f"  Not for {ROLE_NAMES[role]}:", *(f"    {_not_for_name(item)}: {_safe(item.why)}" for item in advice.not_for)]
    return lines


def _not_for_name(item: NotFor) -> str:
    return item.model.id if item.build is None else f"{item.model.id} on {_runtime_label(item.build.runtime)}"


def _lead(advice: Advice, there: bool = False) -> str:
    what = {
        LOCAL: f"an open-weight model on {'that' if there else 'this'} machine.",
        RULES: "the rules (the default, no model), or a small model that fits.",
        API: "a model API.",
    }[advice.lead]
    return f"{what} {advice.lead_why}"


def _runtime_label(runtime: str) -> str:
    return hardware.RUNTIME_NAMES[runtime]


def _option_line(option: Option) -> str:
    build = option.build
    here = ("" if not option.present else ", pulled here" if build.runtime == OLLAMA else ", served here")
    text = f"{option.model.id} on {_runtime_label(build.runtime)} ({_safe(build.model)}{here}): {option.why}"
    if option.verdict == FITS:
        if option.measured:
            text += f"; measured: {_safe(option.measured)} ({MODELS_DOC})"
        else:
            text += f"; fits by size only: not measured for {ROLE_NAMES[option.role]} yet"
    return text


def _price(api: ApiChoice, model: str) -> str:
    price = api.prices.get(model)
    return f"{_dollars(price.input)}/{_dollars(price.output)}" if price is not None else "price unknown"


def _dollars(x: float) -> str:
    return f"${x:.2f}" if x < 1 else f"${x:g}"


def _api_line(api: ApiChoice, role: str) -> str:
    if role == LANES and api.ladder:
        models = ", ".join(f"{m} ({_price(api, m)})" for m in api.ladder)
        what = (f"{api.name}: {models} per million tokens in/out: the ladder and prices "
                f"`flightdeck init --provider {api.provider}` writes")
    elif role == LIGHT and api.light_model:
        what = f"{api.name}: {api.light_model} ({_price(api, api.light_model)} per million tokens in/out)"
    else:
        what = f"{api.name}: choose models on {api.models_page}"
    return f"{api.id}: {what}. {api.note}"


# ---------------------------------------------------------------------- one model


def entry_text(choice: LocalModel | ApiChoice, machine: Machine | None) -> str:
    """One model's details: for a local one, whether each build fits this machine (`machine`),
    how to get it and the config lines that use it; for an API (machine None), its config lines."""
    if isinstance(choice, ApiChoice):
        return _api_entry_text(choice)
    assert machine is not None
    plan = budget(machine)
    model = choice
    offered = " and ".join(ROLE_HEADS[r] for r in model.offered_for)  # a role no build serves is not offered
    use = f"For {offered}." if offered else "Not offered for any role."
    lines = [f"{model.name} ({model.id}): {model.family}, {model.parameters} parameters, {model.license}. {use}"]
    lines.append(f"Measured: {_measured(model)}")
    if any(b.measured or b.not_for for b in model.builds):
        lines.append(APPROXIMATE)
    where = model_catalog.here(machine)
    if machine.described:
        lines.append(f"For the machine described ({_said(machine)}), not this one: whether a build is pulled or served "
                     "there is left out.")
    for build in model.builds:
        found = sizing(build, machine)
        facts = [_safe(build.model)]
        if build.quantization:
            facts.append(_safe(build.quantization))
        if found.sized_by == SIZE_SERVER:
            facts.append(f"{gib(found.size)} on disk, as {_runtime_label(build.runtime)} here gives it")
        else:
            facts.append(f"{gib(build.size)} on disk" if build.size is not None else "size not recorded")
        if found.present:
            facts.append("pulled here" if build.runtime == OLLAMA else "a server here lists it")
        lines += ["", f"On {_runtime_label(build.runtime)}: {', '.join(facts)}"]
        for role in model.roles:
            if role in build.not_for:
                lines.append(f"  not for {ROLE_HEADS[role]}: {_safe(build.not_for[role])}")
            else:
                option = judge(model, build, role, machine, plan)
                lines.append(f"  {where}, for {ROLE_HEADS[role]}: {option.verdict}: {option.why}")
        serves = model.serves(build)
        if not serves:
            continue  # nothing to get it for, and no config lines to give
        lines += ["  get it:", *(f"    {command}" for command in get_commands(build, machine))]
        for role in serves:
            lines.append(f"  {ROLE_HEADS[role]}: {TABLES[role]}")
            lines += _indented(local_lines(build, role))
            check = "try it" if role == LANES else "measure it first"
            lines.append(f"    {check}: {measure_command(build, role)}")
            lines.append(f"    {_init_line(model, role, build)}")
    lines += ["", RECOMMENDS]
    return "\n".join(lines) + "\n"


INIT_JUDGE_ONLY = "   # it writes the judge alone: add the jobs line above"
NO_INIT = ("no `flightdeck init` writes it as measured: init asks a model on this machine for thinking off, so use "
           "the lines above")


def _init_line(model: LocalModel, role: str, build: Build) -> str:
    """The `flightdeck init` that writes a new config with this build in `role`, and what it leaves
    out: init writes the light model for the judge alone, with thinking off."""
    command = init_command(model, role, build)
    if not command:
        return NO_INIT
    more = role == LIGHT and build.light_jobs not in ((), ("judge",))
    return f"or a new config: {command}{INIT_JUDGE_ONLY if more else ''}"


def _measured(model: LocalModel) -> str:
    """The rest of a local model's "Measured:" line: its results, by build and role. A model
    with none but reasons it is not for a role (each with what was measured) points at them."""
    results = "; ".join(f"on {_runtime_label(b.runtime)}, for {ROLE_HEADS[r]}: {_safe(text)}"
                        for b in model.builds for r, text in b.measured.items())
    if results:
        return f"{results} ({MODELS_DOC})."
    if not any(b.not_for for b in model.builds):
        return f"not yet ({MODELS_DOC} has the results)."
    offered = " and ".join(ROLE_HEADS[r] for r in model.offered_for)
    pending = f"not yet for {offered}; " if offered else ""
    return f"{pending}each runtime below says what it is not for, and why ({MODELS_DOC})."


def _api_entry_text(api: ApiChoice) -> str:
    roles = " and ".join(ROLE_HEADS[r] for r in api.roles)
    lines = [f"{api.name} ({api.id}). For {roles}.", api.note]
    if api.models_page:
        lines.append(f"Its models: {api.models_page}. Replace the capitalised placeholders below with their ids.")
    for role in api.roles:
        lines += ["", f"{ROLE_HEADS[role]}: {TABLES[role]}", *_indented(api_lines(api, role))]
        if role == LIGHT:
            lines.append(f"    measure it first: {api_measure_command(api)}")
        init = init_command(api, role)
        if init:
            lines.append(f"    or a new config: {init}")
    lines += ["", RECOMMENDS]
    return "\n".join(lines) + "\n"


def api_measure_command(api: ApiChoice) -> str:
    """The eval-local that measures the API's light model against the rules."""
    if api.provider == "anthropic":
        return f"flightdeck eval-local --engine anthropic --model {api.light_model or 'MODEL'}"
    return (f"flightdeck eval-local --engine openai --model {api.light_model or 'MODEL'} --base-url {api.base_url} "
            f"--key-env {api.key_env}")


def _indented(block: str) -> list[str]:
    return [f"    {line}" if line else "" for line in block.rstrip("\n").split("\n")]


def _safe(text: str) -> str:
    return untrusted(text, one_line=True)


# ---------------------------------------------------------------------- JSON


def overview_json(catalog: Catalog, machine: Machine) -> dict:
    plan = budget(machine)
    roles = {}
    config_state = this_config() if not machine.described else (None, "")
    for role in ROLES:
        advice = advise(catalog, machine, role, plan)
        roles[role] = advice_json(advice)
        if role == LANES:
            context = lane_context(machine, advice, config_state)
            roles[role]["ollama_context"] = context.data if context is not None else None
    return {
        "described": machine.described,  # true: the machine --memory describes, not this one
        "machine": machine.as_json(),
        "local_models": {"where": plan.where, "memory_bytes": plan.bytes, "why": plan.why},
        "memory_rule": {"text": MEMORY_RULE, "estimate": True,
                        "context_allowance_bytes": dict(CONTEXT_ALLOWANCE)},
        "roles": roles,
        "measured_results": MODELS_DOC,
        "approximate": APPROXIMATE,
        "coding_agents": AGENTS,
        "changes_config": False,
    }


def advice_json(advice: Advice) -> dict:
    data = {
        "where": advice.where,
        "lead": advice.lead,
        "why": advice.lead_why,
        "fits": [option_json(o) for o in advice.fits],
        "too_big": [option_json(o) for o in advice.too_big],
        "cannot_tell": [option_json(o) for o in advice.cannot_tell],
        "not_here": [option_json(o) for o in advice.not_here],
        "not_for": [not_for_json(item) for item in advice.not_for],
        "api": [api_json(a) for a in advice.api],
    }
    if advice.role == LIGHT:
        data["default"] = RULES
    return data


def option_json(option: Option) -> dict:
    build = option.build
    basis = None if option.verdict != FITS else "measured" if option.measured else "size only"  # why it is offered
    data = {
        "id": option.model.id, "name": option.model.name, "runtime": build.runtime, "model": build.model,
        "quantization": build.quantization, "size_bytes": build.size, "weights_bytes": option.size,
        "sized_by": option.sized_by or None, "server_args": list(build.server_args), "verdict": option.verdict,
        "need_bytes": option.need, "estimate": True, "why": option.why, "present": option.present,
        "measured": option.measured or None, "basis": basis,
    }
    if option.role == LIGHT:
        data.update(light_json(build))
    return data


def light_json(build: Build) -> dict:
    """What a build's light role is, for scripts: the run jobs it is offered for, the [light]
    thinking it was measured with (None: flightdeck's default), and its jobs table's figures."""
    return {"light_jobs": list(build.light_jobs), "thinking": build.thinking,
            "jobs": jobs_data(build.jobs, build.light_jobs) if build.jobs is not None else None}


def not_for_json(item: NotFor) -> dict:
    """A model (runtime None) or one build the catalog does not offer for the role, and why."""
    build = item.build
    return {"id": item.model.id, "runtime": build.runtime if build else None, "model": build.model if build else None,
            "why": item.why}


def api_json(api: ApiChoice) -> dict:
    return {
        "id": api.id, "name": api.name, "provider": api.provider, "roles": list(api.roles),
        "classifier": api.classifier, "note": api.note, "models_page": api.models_page or None,
        "base_url": api.base_url, "key_env": api.key_env, "ladder": list(api.ladder),
        "prices": {m: {"input": p.input, "output": p.output, "cached_input": p.cached_input, "cache_write": p.cache_write}
                   for m, p in api.prices.items()},
        "light_model": api.light_model or None,
    }


def entry_json(choice: LocalModel | ApiChoice, machine: Machine | None) -> dict:
    if isinstance(choice, ApiChoice):
        roles = {
            role: {"config": api_lines(choice, role), "replaces": TABLES[role],
                   "check": api_measure_command(choice) if role == LIGHT else None,
                   "init": init_command(choice, role) or None}
            for role in choice.roles
        }
        return {**api_json(choice), "use": roles, "changes_config": False}
    assert machine is not None
    plan = budget(machine)
    builds = []
    for build in choice.builds:
        found = sizing(build, machine)
        options = {role: judge(choice, build, role, machine, plan) for role in choice.serves(build)}
        roles = {
            role: {
                "verdict": option.verdict, "need_bytes": option.need, "estimate": True, "why": option.why,
                "measured": option.measured or None, "config": local_lines(build, role), "replaces": TABLES[role],
                "check": measure_command(build, role), "init": init_command(choice, role, build) or None,
            }
            for role, option in options.items()
        }
        builds.append({
            "runtime": build.runtime, "model": build.model, "quantization": build.quantization, "size_bytes": build.size,
            "weights_bytes": found.size, "sized_by": found.sized_by or None, "present": found.present,
            "server_args": list(build.server_args), "measured": dict(build.measured), "not_for": dict(build.not_for),
            "get": get_commands(build, machine) if roles else [], "roles": roles,
            **(light_json(build) if LIGHT in choice.roles else {}),
        })
    return {
        "id": choice.id, "name": choice.name, "family": choice.family, "parameters": choice.parameters,
        "license": choice.license, "roles": list(choice.offered_for),  # a build's not_for says why not the others
        "measured_results": MODELS_DOC, "builds": builds, "local_models": {"where": plan.where, "memory_bytes": plan.bytes},
        "described": machine.described,
        "changes_config": False,
    }
