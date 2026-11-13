"""ctf engines list | show | route | lint | generate | coverage | usage (B-186, R-10)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HELP = "engine manifests: list, show, route, lint, generate, coverage matrix, real-use counts"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    ls = sp.add_parser("list", help="every manifested engine")
    ls.add_argument("--lane")
    ls.add_argument("--capability", help="only engines with this capability tag")
    ls.add_argument("--unrouted", action="store_true", help="only engines with no route")
    sh = sp.add_parser("show", help="one engine's manifest")
    sh.add_argument("engine")
    rt = sp.add_parser("route", help="which engines the manifests route a challenge to")
    rt.add_argument("category")
    rt.add_argument("description", nargs="?", default="")
    rt.add_argument("--files", type=Path, help="the challenge's files folder")
    li = sp.add_parser("lint", help="route lint; exit 1 on an error not in the baseline")
    li.add_argument("--all", action="store_true", help="also print known (baselined) findings")
    li.add_argument("--shrink-baseline", action="store_true",
                    help="drop baseline lines that no longer fire (never adds)")
    ge = sp.add_parser("generate", help="write an inferred manifest for every engine module without one, then "
                                        "the files generated from the manifests (triage route table, "
                                        "docs/CAPABILITIES.md, coverage matrix)")
    gg = ge.add_mutually_exclusive_group()
    gg.add_argument("--dry-run", action="store_true", help="say what would be written; write nothing")
    gg.add_argument("--check", action="store_true",
                    help="exit 1 when an engine has no manifest or a generated file is stale; write nothing")
    ge.add_argument("--file-routes", action="store_true",
                    help="also append a file route to each unrouted engine whose code tests for a distinctive "
                         "format (magic bytes or extension)")
    co = sp.add_parser("coverage", help="the docs/coverage/ENGINES.md matrix")
    g = co.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true", help="exit 1 when the committed file is stale")
    g.add_argument("--print", action="store_true")
    us = sp.add_parser("usage", help="real-use counts from engine.run ledger records")
    us.add_argument("--workdir", type=Path, action="append",
                    help="an event workdir (repeatable; default: the current one)")


def _list(args) -> int:
    from ..engines import manifest
    for m in manifest.discover():
        if args.lane and m.lane != args.lane:
            continue
        if args.capability and not m.has(args.capability):
            continue
        if args.unrouted and m.routes:
            continue
        cls = next((c for c in m.capabilities if c in ("executes", "analysis", "plan", "library")), "?")
        print(f"{m.id:45} {cls:9} {m.status:11} {len(m.routes):>2} route(s)  {m.rel_module()}")
    return 0


def _show(args) -> int:
    from ..engines import runner
    m = runner.resolve(args.engine)
    print(m.path.read_text(encoding="utf-8"), end="")
    return 0


def _route(args) -> int:
    from ..engines import router
    hits = router.route(args.category, args.description, args.files)
    for h in hits:
        print(f"{h.priority:>3}  {h.manifest.id:45} {h.reason}")
    if not hits:
        print("no engine routes this challenge", file=sys.stderr)
    return 0


def _lint(args) -> int:
    from ..engines import lint
    baseline = lint.load_baseline()
    findings = lint.lint(baseline=baseline)
    stale = lint.stale_baseline(findings, baseline)
    if args.shrink_baseline:
        if stale:
            lint.write_baseline(baseline - stale)
        print(f"baseline: dropped {len(stale)} line(s) that no longer fire")
        stale = set()
    errors = [f for f in findings if f.severity == "error"]
    for f in findings:
        if f.severity != "known" or args.all:
            print(f.line())
    known = sum(1 for f in findings if f.severity == "known")
    warnings = sum(1 for f in findings if f.severity == "warning")
    for code, subject in sorted(stale):
        print(f"error   stale-baseline       {code} {subject}: no longer fires; run "
              "`python -m ctf engines lint --shrink-baseline`")
    print(f"{len(errors)} error(s), {warnings} warning(s), {known} known (baseline {lint.BASELINE_REL}), "
          f"{len(stale)} stale baseline line(s)", file=sys.stderr)
    return 1 if errors or stale else 0


def _generate(args) -> int:
    from ..engines import derived, fileroutes, generate
    planned, skipped = generate.plan()
    for s in skipped:
        print(f"skipped: {s}", file=sys.stderr)
    froutes, fskipped = fileroutes.plan() if args.file_routes else ([], [])
    for s in fskipped:
        print(f"no file route: {s}", file=sys.stderr)
    if args.check or args.dry_run:
        stale = derived.stale()
        for p in planned:
            print(f"missing manifest: {p.sidecar}" if args.check else p.sidecar)
        for p in froutes:
            print(f"file route: {p.manifest.id} {', '.join(p.files)} priority {p.priority}")
        for rel in stale:
            print(f"stale: {rel}")
        print(f"{len(planned)} manifest(s) {'missing' if args.check else 'would be written'}, "
              f"{len(froutes)} file route(s) to add, {len(stale)} stale generated file(s)", file=sys.stderr)
        if args.check:
            if planned or froutes or stale:
                print("run `python -m ctf engines generate" + (" --file-routes" if froutes else "") + "`",
                      file=sys.stderr)
                return 1
        return 0
    n = generate.write(planned)
    print(f"wrote {n} manifest(s)", file=sys.stderr)
    if froutes:
        print(f"appended {fileroutes.apply(froutes)} file route(s)", file=sys.stderr)
    for rel in derived.write_all():
        print(f"regenerated {rel}", file=sys.stderr)
    return 1 if skipped else 0


def _coverage(args) -> int:
    from ..engines import coverage
    if args.print:
        print(coverage.render(), end="")
        return 0
    if args.write:
        print(f"wrote {coverage.write()}", file=sys.stderr)
        return 0
    if coverage.is_stale():
        print(f"{coverage.MATRIX_REL} is stale: run `python -m ctf engines coverage --write`", file=sys.stderr)
        return 1
    print(f"{coverage.MATRIX_REL} is current", file=sys.stderr)
    return 0


def _usage(args) -> int:
    from .. import paths
    from ..engines import manifest, usage
    wds = args.workdir or [paths.workdir()]
    print(usage.report(usage.collect(wds), manifest.discover()))
    return 0


def run(args: argparse.Namespace) -> int:
    from ..engines import manifest, routetable, runner
    from ..event import EventError
    try:
        return {"list": _list, "show": _show, "route": _route, "lint": _lint, "generate": _generate,
                "coverage": _coverage, "usage": _usage}[args.action](args)
    except (manifest.ManifestError, runner.EngineError, routetable.RouteTableError, EventError) as e:
        print(f"ctf engines: {e}", file=sys.stderr)
        return 2
