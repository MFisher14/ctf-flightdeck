"""`flightdeck models`: which models fit this machine, and where flightdeck would use each.

cli.py mounts models_command onto the root CLI, in the "Set up" panel.

It looks at this machine (hardware.py: each probe with a short timeout, no root, nothing
contacted but 127.0.0.1), matches the model catalog against it (model_catalog.py, models.toml)
and prints, per role, the models that fit and why, those that do not and why, which were
measured (docs/MODELS.md) and which only fit by size, then the model APIs. `flightdeck models ID`
says how to get that model and the exact config lines that use it. --json prints the same as
JSON, for scripts.

It recommends: it never picks for the player, and never writes or changes a config.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from . import hardware
from .hardware import DOWN, LLAMA_CPP, LM_STUDIO, MLX, OLLAMA, SERVING, Machine, Runtime, gib
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
    LIGHT: "Light role: [light], small classification jobs (today the hint judge). The default is the rules, "
           "no model; measure a model with `flightdeck eval-local` before you switch it on.",
}
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
    LIGHT: "in your config, these replace its [light] table:",
}
RECOMMENDS = "This only recommends: it never changes your config."
AGENTS = ("Coding-agent lanes (`flightdeck play --agent claude` or `codex`) bring their own models: [agents] in your "
          "config, not this list.")


def this_machine() -> Machine:
    """This machine's facts: hardware.probe() on hardware.RealHost (a test swaps in a fake host)."""
    return hardware.probe()


def models_command(
    entry: Annotated[
        str | None,
        typer.Argument(metavar="ID", show_default=False,
                       help="A model from the list: how to get it, and the config lines that use it."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the same as JSON, for scripts.")] = False,
) -> None:
    """Which models fit this machine, and where flightdeck would use each: local open-weight
    models first, then model APIs. It recommends; it never changes your config."""
    try:
        catalog = load_catalog()
    except CatalogError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    if entry is None:
        machine = this_machine()
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
    machine = None if isinstance(choice, ApiChoice) else this_machine()  # an API: nothing here to look at
    if as_json:
        typer.echo(json.dumps(entry_json(choice, machine), indent=2))
    else:
        typer.echo(entry_text(choice, machine), nl=False)


# ---------------------------------------------------------------------- the overview


def overview_text(catalog: Catalog, machine: Machine) -> str:
    plan = budget(machine)
    lines = ["This machine", *machine_lines(machine), "", f"{_budget_line(plan)}.", MEMORY_RULE]
    for role in ROLES:
        lines += ["", *role_lines(advise(catalog, machine, role, plan))]
    example = next((o.model.id for role in ROLES for o in advise(catalog, machine, role, plan).fits), catalog.local[0].id)
    lines += [
        "",
        AGENTS,
        f"Measured results: {MODELS_DOC}. How to get a model and the config lines that use it: "
        f"flightdeck models ID (for example: flightdeck models {example}).",
        RECOMMENDS,
    ]
    return "\n".join(lines) + "\n"


def _budget_line(plan: Budget) -> str:
    if plan.bytes is None:
        return f"Local models: flightdeck cannot tell what fits here: {plan.why}"
    return f"Local models may use about {gib(plan.bytes)} here: {plan.why}"


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


def role_lines(advice: Advice) -> list[str]:
    """One role's section: what comes first and why, the local models (fit, too big, cannot
    tell, not for this machine, not for this role) and the model APIs, in the order the advice
    leads with."""
    role = advice.role
    lines = [ROLE_TITLES[role], f"  First: {_lead(advice)}"]
    fits = [f"    {_option_line(o)}" for o in advice.fits]
    fit_here = "  Fit here, on the CPU (slow):" if advice.where == CPU else "  Fit here:"
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
        lines += ["  Do not fit here:", *(f"    {_option_line(o)}" for o in advice.too_big)]
    if advice.cannot_tell:
        lines += ["  Cannot tell:", *(f"    {_option_line(o)}" for o in advice.cannot_tell)]
    if advice.not_here:
        named = ", ".join(f"{o.model.id} on {_runtime_label(o.build.runtime)}" for o in advice.not_here)
        why = "; ".join(dict.fromkeys(o.why for o in advice.not_here))
        lines.append(f"  Not for this machine: {named} ({why})")
    if advice.not_for:
        lines += [f"  Not for {ROLE_NAMES[role]}:", *(f"    {_not_for_name(item)}: {_safe(item.why)}" for item in advice.not_for)]
    return lines


def _not_for_name(item: NotFor) -> str:
    return item.model.id if item.build is None else f"{item.model.id} on {_runtime_label(item.build.runtime)}"


def _lead(advice: Advice) -> str:
    what = {
        LOCAL: "an open-weight model on this machine.",
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
                lines.append(f"  here, for {ROLE_HEADS[role]}: {option.verdict}: {option.why}")
        serves = model.serves(build)
        if not serves:
            continue  # nothing to get it for, and no config lines to give
        lines += ["  get it:", *(f"    {command}" for command in get_commands(build, machine))]
        for role in serves:
            lines.append(f"  {ROLE_HEADS[role]}: {TABLES[role]}")
            lines += _indented(local_lines(build, role))
            check = "try it" if role == LANES else "measure it first"
            lines.append(f"    {check}: {measure_command(build, role)}")
            lines.append(f"    or a new config: {init_command(model, role, build)}")
    lines += ["", RECOMMENDS]
    return "\n".join(lines) + "\n"


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
    return {
        "machine": machine.as_json(),
        "local_models": {"where": plan.where, "memory_bytes": plan.bytes, "why": plan.why},
        "memory_rule": {"text": MEMORY_RULE, "estimate": True,
                        "context_allowance_bytes": dict(CONTEXT_ALLOWANCE)},
        "roles": {role: advice_json(advise(catalog, machine, role, plan)) for role in ROLES},
        "measured_results": MODELS_DOC,
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
    return {
        "id": option.model.id, "name": option.model.name, "runtime": build.runtime, "model": build.model,
        "quantization": build.quantization, "size_bytes": build.size, "weights_bytes": option.size,
        "sized_by": option.sized_by or None, "server_args": list(build.server_args), "verdict": option.verdict,
        "need_bytes": option.need, "estimate": True, "why": option.why, "present": option.present,
        "measured": option.measured or None, "basis": basis,
    }


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
        "prices": {m: {"input": p.input, "output": p.output, "cached_input": p.cached_input} for m, p in api.prices.items()},
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
                "check": measure_command(build, role), "init": init_command(choice, role, build),
            }
            for role, option in options.items()
        }
        builds.append({
            "runtime": build.runtime, "model": build.model, "quantization": build.quantization, "size_bytes": build.size,
            "weights_bytes": found.size, "sized_by": found.sized_by or None, "present": found.present,
            "server_args": list(build.server_args), "measured": dict(build.measured), "not_for": dict(build.not_for),
            "get": get_commands(build, machine) if roles else [], "roles": roles,
        })
    return {
        "id": choice.id, "name": choice.name, "family": choice.family, "parameters": choice.parameters,
        "license": choice.license, "roles": list(choice.offered_for),  # each build's not_for says why a role is not
        "measured_results": MODELS_DOC, "builds": builds, "local_models": {"where": plan.where, "memory_bytes": plan.bytes},
        "changes_config": False,
    }
