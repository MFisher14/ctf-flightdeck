"""The B-201 model router in the agent launchers (tools/codex_launch, tools/claude_launch).

    add_route_options(parser)                       # --difficulty, --category, --no-route
    route = route_for(args, "codex")               # ctf.router.Route, or None (said on stderr)
    tier = apply_route(route, args, "codex")       # fills --model / --effort the caller left unset

When is a launch routed. Only when the event profile has a [routing] table (the event opted in) and the
launch names a role (--role / $CTF_ROLE, B-096). Then the route for (role, --difficulty or
$CTF_DIFFICULTY, the launcher's harness, --category or $CTF_CATEGORY) fills whatever the caller did
not give: --model (when the route names a model of this harness) and --effort. An explicit --model or
--effort always wins, and the launcher says so. The route's fields (difficulty, effort, tier, route,
category, tier_budget_usd) are recorded on agent_launch by the gate with the role, so the escalator
(ctf/escalation.py) reads the challenge's difficulty and its first agent's launched effort back
(`effort` is the effort launched, an explicit --effort included).

Loud, never silent:
  * --difficulty or --category on an event with no [routing] table, with no event, or without a
    role is a RouteLaunchError (the launcher exits 2), as is --no-route together with them;
  * a profile whose [routing] the price table rejects is a RouteLaunchError naming each problem;
  * a role on an opted-in event with no route model for this harness prints the route's note and
    leaves the CLI's default model.

Speed tiers (B-009, B-033): a route with a tier other than "default" applies only when its model is the
one launched. Then the run must be budget-gated (--challenge) and metered (codex exec, not the TUI);
the gate's agent_cap_usd is the route's budget_usd, and the usage reader prices the tier's multiplier.
claude_launch cannot pin a Claude speed tier and refuses such a route by name. Anything else is a
RouteLaunchError before the gate admits the run.
"""
from __future__ import annotations

import sys

from ctf import env as _env
from ctf import event as _event
from ctf import paths as _paths
from ctf import router as _router
from tools import launch_gate as _gate


class RouteLaunchError(ValueError):
    """The launch's routing options cannot be honoured; the launcher exits 2 with this message."""


def add_route_options(p) -> None:
    p.add_argument("--difficulty", choices=_router.DIFFICULTIES,
                   help="the challenge's difficulty for the B-201 model router (default $CTF_DIFFICULTY, "
                        "else the profile's routing.default_difficulty); needs --role and a [routing] table")
    p.add_argument("--category", help="the challenge's category for the router's top_categories rule "
                   "(default $CTF_CATEGORY)")
    p.add_argument("--no-route", action="store_true",
                   help="do not route this launch even when the profile has a [routing] table")


def passthrough_model(extra) -> str | None:
    """The model a claude passthrough names (`--model M` / `--model=M`), else None. Such a model wins
    over the route's (an explicit choice)."""
    extra = list(extra)
    for i, a in enumerate(extra):
        if a == "--model":
            if i + 1 >= len(extra) or not extra[i + 1].strip():
                raise RouteLaunchError("passthrough --model needs a value")
            return extra[i + 1]
        if a.startswith("--model="):
            v = a.split("=", 1)[1]
            if not v.strip():
                raise RouteLaunchError("passthrough --model needs a value")
            return v
    return None


def _opt(args, name: str, env_name: str) -> str | None:
    v = getattr(args, name, None)
    if v is None:
        v = _env.get(env_name)
    v = v.strip() if isinstance(v, str) else v
    return v or None


def route_for(args, harness: str, *, err=None) -> _router.Route | None:
    """The route for this launch, or None when the launch is not routed (said on stderr when the event
    opted in). Raises RouteLaunchError (named) when the routing options cannot be honoured."""
    err = err if err is not None else sys.stderr
    difficulty = _opt(args, "difficulty", "CTF_DIFFICULTY")
    category = _opt(args, "category", "CTF_CATEGORY")
    asked = [n for n, v in (("--difficulty", difficulty), ("--category", category)) if v]
    if difficulty is not None and difficulty not in _router.DIFFICULTIES:
        raise RouteLaunchError(f"unknown difficulty {difficulty!r}; one of: {', '.join(_router.DIFFICULTIES)}")
    if getattr(args, "no_route", False):
        if asked:
            raise RouteLaunchError(f"--no-route contradicts {' and '.join(asked)}")
        return None
    try:
        role = _gate.role_from(getattr(args, "role", None))
    except _gate.GateError as e:
        raise RouteLaunchError(str(e)) from None
    slug = getattr(args, "event", None) or _env.get("CTF_EVENT")
    if not slug:
        if asked:
            raise RouteLaunchError(f"{' and '.join(asked)} need an event profile with a [routing] table "
                                   "(--event or CTF_EVENT)")
        return None
    try:
        profile = _event.load(slug)
    except _event.EventError as e:
        if asked:
            raise RouteLaunchError(f"{' and '.join(asked)}: {e}") from None
        return None         # the fence step reports an unloadable profile by name
    if profile.routing is None:
        if asked:
            raise RouteLaunchError(f"{' and '.join(asked)} given but event {profile.slug!r} has no "
                                   "[routing] table (B-201): nothing to route by")
        return None
    if role is None:
        if asked:
            raise RouteLaunchError(f"{' and '.join(asked)} need a role (--role or CTF_ROLE) to route by")
        print(f"model route: off: event {profile.slug!r} has a [routing] table but this launch names no "
              "role (--role or CTF_ROLE)", file=err)
        return None
    try:
        r = _router.Router.from_profile(profile, workdir=_paths.workdir(profile.slug))
        return r.resolve(role, difficulty, harness=harness, category=category)
    except _router.RouterError as e:
        raise RouteLaunchError(str(e)) from None


def apply_route(route: _router.Route | None, args, harness: str, *, err=None) -> str:
    """Fill args.model / args.effort from `route` where the caller left them unset and return the speed
    tier this launch runs at ("default" unless the route's own model is the one launched). Prints what
    it routed. A speed tier on claude_launch is a RouteLaunchError."""
    err = err if err is not None else sys.stderr
    if route is None:
        return "default"
    for note in route.notes:
        print(f"model route: {note}", file=err)
    if getattr(args, "model", None) is None and route.model is not None:
        args.model = route.model
    elif getattr(args, "model", None) is not None and route.model not in (None, args.model):
        print(f"model route: --model {args.model} given; the route's {route.model} is not used", file=err)
    if getattr(args, "effort", None) is None:
        args.effort = route.effort
    elif args.effort != route.effort:
        print(f"model route: --effort {args.effort} given; the route's {route.effort} is not used", file=err)
    tier = route.tier if (route.speed_tier and route.model is not None and args.model == route.model) \
        else "default"
    if tier != "default" and harness == "claude":
        raise RouteLaunchError(f"the route for {route.role}/{route.difficulty} names speed tier {tier!r} "
                               f"for {route.model}; claude_launch cannot pin a Claude speed tier. Route "
                               "it on the default tier, or launch with --no-route")
    print(f"model route: {route.role}/{route.difficulty} ({route.source}) -> model "
          f"{args.model or '<CLI default>'}, effort {args.effort}, tier {tier}"
          + (f", budget ${route.budget_usd:g}" if tier != "default" else ""), file=err)
    return tier


def check_speed_tier(route: _router.Route | None, tier: str, *, gate, metered: bool) -> None:
    """A speed tier (anything but "default") needs a budget-gated, metered run (B-033): refuse it
    otherwise. On success the gate's agent_cap_usd becomes the route's budget_usd."""
    if tier == "default":
        return
    if route is None or route.budget_usd is None:
        raise RouteLaunchError(f"speed tier {tier!r} has no explicit budget_usd (B-033); refused")
    if gate is None:
        raise RouteLaunchError(f"speed tier {tier!r} needs a budget-gated launch (--challenge or "
                               "CTF_CHALLENGE) so its budget_usd can be enforced; refused (B-009 keeps it "
                               "off otherwise)")
    if not metered:
        raise RouteLaunchError(f"speed tier {tier!r} needs a metered run (codex exec, not the TUI) so its "
                               "spend can be counted against budget_usd; refused")
    gate.agent_cap_usd = float(route.budget_usd)


def record_route(gate, route: _router.Route | None, tier: str, *, effort: str | None = None) -> None:
    """Put the route's fields on the gate's agent_launch record (no-op without a gate or a route).
    `effort` is the effort this launch actually runs at (args.effort after apply_route: an explicit
    --effort wins over the route's); it is recorded so the escalator's ramp starts from it."""
    if gate is None or route is None:
        return
    fields = route.ledger_fields()
    fields["tier"] = tier
    if effort:
        fields["effort"] = effort
    if tier == "default":
        fields.pop("tier_budget_usd", None)
    gate.launch_fields = fields
