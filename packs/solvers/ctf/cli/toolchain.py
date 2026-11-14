"""ctf toolchain — pinned images, assets, the lane env-check, version notes, the wheelhouse (B-188).

    python -m ctf toolchain [--root DIR] <command> ...      (--root: another checkout's manifests)
    python -m ctf toolchain lint     [--only NAME ...] [--json]
    python -m ctf toolchain status   [--only NAME ...] [--json]
    python -m ctf toolchain build    [--only NAME ...] [--force] [--apply] [--json]
    python -m ctf toolchain smoke    NAME ...
    python -m ctf toolchain assets   [--only NAME ...] [--json]
    python -m ctf toolchain env      [--write]
    python -m ctf toolchain envcheck LANE [--python PY] [--no-pins] [--json]
    python -m ctf toolchain versions DIR [--json]
    python -m ctf toolchain wheels   [--dir DIR] [--plan] [--json]

lint      the static checks of tools/images.toml and every Dockerfile it names (no docker). Exit 1 when
          a pinned image has a finding, 2 on an unreadable manifest. Findings of an unpinned image and
          unlocked downloads are printed, never fatal.
status    each image's local state from `docker image inspect` (a read): ok, stale (its label is not the
          hash of the current files), unlabelled, missing, unknown. Exit 1 when a core image is not ok.
build     the build plan, a DRY RUN unless --apply: what is missing or stale is built, a fresh image is
          skipped (no repeated rebuilds), an image another tool builds is skipped, an image with an
          unlocked download or (pinned) a lint finding is refused, so nothing is built and labelled
          fresh that `lint` fails. --apply runs `docker build` in a staged context. Exit 0 nothing
          left to do (or every build passed), 1 a build failed or was refused, 2 docker absent.
smoke     the images' env-check commands, each in a fresh container with no network. Exit 1 on a failure.
assets    tools/assets.toml resolved. Exit 1 when a core asset is not ok.
env       `export` lines for a shell: CTF_PYTHON, PYTHONPATH (the engine sys.path), every ok asset, the
          venv's bin folder in front of PATH. Use: eval "$(python -m ctf toolchain env)". --write also
          writes them to <workdir>/toolchain/env.sh.
envcheck  the lane's env-check: modules its engines import, its binaries and assets, the venv pins. Run it
          first in a fresh lane. Exit 1 when a required item is missing, 2 on an unknown lane.
versions  version notes in a challenge folder (Sage, Python, glibc, Ubuntu, pins, FROM lines) and the
          tagged image each tool should run in. Exit 1 when a noted version has no image or the notes
          conflict, 2 when DIR is not a folder.
wheels    is every requirements.txt pin in the wheelhouse ($CTF_WHEELHOUSE, default
          ~/ctf-work/_wheelhouse)? --plan prints the commands that fill it (network: a human step) and
          install from it offline. Exit 1 when a pin is missing, 2 when the folder is not there.

Under CTF_TESTING docker must be a test stub (exit 2 otherwise): no test talks to a real docker.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import paths
from ..toolchain import assets as _assets
from ..toolchain import images as _images
from ..toolchain import lanes as _lanes
from ..toolchain import versions as _versions
from ..toolchain import wheels as _wheels

HELP = "pinned toolchain (B-188): image lint/status/build/smoke, assets, lane env-check, version notes, wheels"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", metavar="DIR", type=Path,
                   help="the checkout whose tools/images.toml, assets.toml, lanes.toml and requirements are "
                        "read (default: this one)")
    sub = p.add_subparsers(dest="toolchain_cmd", required=True)
    for name, help_ in (("lint", "static checks of the image manifest and Dockerfiles"),
                        ("status", "local image state from docker image inspect (a read)")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--only", nargs="+", metavar="NAME")
        s.add_argument("--json", action="store_true")
    b = sub.add_parser("build", help="plan the image builds (a dry run); --apply runs them")
    b.add_argument("--only", nargs="+", metavar="NAME")
    b.add_argument("--force", action="store_true", help="rebuild fresh images too")
    b.add_argument("--apply", action="store_true", help="run docker build")
    b.add_argument("--json", action="store_true")
    s = sub.add_parser("smoke", help="run the images' env-check commands, networkless")
    s.add_argument("names", nargs="+", metavar="NAME")
    a = sub.add_parser("assets", help="resolve tools/assets.toml")
    a.add_argument("--only", nargs="+", metavar="NAME")
    a.add_argument("--json", action="store_true")
    e = sub.add_parser("env", help="export lines for a lane shell (eval them)")
    e.add_argument("--write", action="store_true", help="also write <workdir>/toolchain/env.sh")
    c = sub.add_parser("envcheck", help="the lane env-check an agent runs first")
    c.add_argument("lane")
    c.add_argument("--python", metavar="PY", help="the interpreter the lane runs (default: this one)")
    c.add_argument("--no-pins", action="store_true", help="skip the venv pin check")
    c.add_argument("--json", action="store_true")
    v = sub.add_parser("versions", help="version notes in a challenge folder and the image to use")
    v.add_argument("dir")
    v.add_argument("--json", action="store_true")
    w = sub.add_parser("wheels", help="check the wheelhouse against requirements.txt")
    w.add_argument("--dir", metavar="DIR", help="the wheelhouse (default $CTF_WHEELHOUSE or ~/ctf-work/_wheelhouse)")
    w.add_argument("--plan", action="store_true", help="print the fill and offline-install commands")
    w.add_argument("--json", action="store_true")


def _err(msg: str) -> int:
    print(f"ctf toolchain: {msg}", file=sys.stderr)
    return 2


def _lint(args) -> int:
    imgs = _images.select(_images.load(_images.manifest_path(args.root)), args.only)
    findings = _images.lint(imgs, args.root)
    errs = _images.errors(findings, imgs)
    unlocked = [(i.name, d.name) for i in imgs for d in i.unlocked()]
    if args.json:
        print(json.dumps({"passed": not errs, "findings": [vars(f) | {"fatal": f in errs} for f in findings],
                          "unlocked": [list(u) for u in unlocked]}, indent=1))
        return 1 if errs else 0
    print(f"toolchain images ({_images.MANIFEST_REL}): {len(imgs)} image(s)")
    for f in findings:
        print(("  FAIL " if f in errs else "  note ") + f.render())
    for im in imgs:
        if not im.pinned:
            print(f"  unpinned {im.name}: {im.unpinned_reason}")
    for name, dl in unlocked:
        print(f"  unlocked {name}: download {dl!r} has no sha256 yet (the build is refused until it is recorded)")
    print("LINT " + ("OK" if not errs else f"FAILED: {len(errs)} finding(s) on pinned images"))
    return 1 if errs else 0


def _status(args) -> int:
    imgs = _images.select(_images.load(_images.manifest_path(args.root)), args.only)
    report = _images.status(imgs, root=args.root)
    core = _images.problems(report, core_only=True)
    if args.json:
        print(json.dumps({"passed": not core, "images": [s.to_dict() for s in report]}, indent=1))
    else:
        for s in report:
            print("  " + s.line().replace("\n", "\n  "))
        print("IMAGES " + ("OK" if not core else "PROBLEMS: " + ", ".join(s.name for s in core)))
    return 1 if core else 0


def _build(args) -> int:
    imgs = _images.select(_images.load(_images.manifest_path(args.root)), args.only)
    report = _images.status(imgs, root=args.root)
    steps = _images.plan_build(imgs, report, root=args.root, force=args.force)
    results = _images.apply_build(steps, imgs, root=args.root) if args.apply else None
    if args.json:
        doc = {"apply": args.apply, "steps": [{"image": s.image, "action": s.action, "reason": s.reason,
                                               "argv": list(s.argv) if s.argv else None} for s in steps]}
        if results is not None:
            doc["results"] = [{"image": r.step.image, "returncode": r.returncode, "reason": r.reason,
                               "output": r.output[-2000:]} for r in results]
        print(json.dumps(doc, indent=1))
    else:
        print("build plan" + ("" if args.apply else " (DRY RUN: nothing runs without --apply)") + ":")
        for s in steps:
            print("  " + s.render())
        for r in results or ():
            if r.reason == "" and r.returncode == 0:
                print(f"  BUILT  {r.step.image} ({r.step.tag})")
            elif r.reason == "":
                print(f"  FAILED {r.step.image}: exit {r.returncode}\n    " + "\n    ".join(r.output.strip().splitlines()[-15:]))
            elif r.reason == "absent":
                print(f"  ABSENT {r.step.image}: {r.output}")
    if results is not None and any(r.reason == "absent" for r in results):
        return 2
    refused = any(s.action == "refused" for s in steps)
    if results is None:
        return 1 if refused or any(s.action == "build" for s in steps) else 0
    failed = any(r.reason == "" and r.returncode != 0 for r in results)
    return 1 if failed or refused else 0


def _smoke(args) -> int:
    imgs = _images.select(_images.load(_images.manifest_path(args.root)), args.names)
    bad = 0
    for im in imgs:
        for r in _images.smoke(im):
            ok = r.ok
            bad += not ok
            print(f"  {'OK  ' if ok else 'FAIL'} {im.name}: {' '.join(r.argv)}"
                  + ("" if ok else f" (exit {r.returncode}): {r.output.strip()[-300:]}"))
    print("SMOKE " + ("OK" if not bad else f"FAILED: {bad} command(s)"))
    return 1 if bad else 0


def _assets_cmd(args) -> int:
    items = _assets.load(_assets.manifest_path(args.root))
    report = _assets.resolve(items, only=args.only)
    core = _assets.problems(report, core_only=True)
    if args.json:
        print(json.dumps({"passed": not core, "assets": [s.to_dict() for s in report],
                          "exports": _assets.exports(items, report)}, indent=1))
    else:
        print(f"assets ({_assets.MANIFEST_REL}):")
        for s in report:
            print("  " + s.line().replace("\n", "\n  "))
        print("ASSETS " + ("OK" if not core else "PROBLEMS: " + ", ".join(s.name for s in core)))
    return 1 if core else 0


def _env(args) -> int:
    values, prepend = _lanes.exports(root=args.root)
    text = _assets.render_env(values, path_prepend=prepend)
    sys.stdout.write(text)
    if args.write:
        try:
            d = paths.workdir() / "toolchain"
        except _event.EventError as e:
            return _err(f"--write needs the event workdir: {e}")
        d.mkdir(parents=True, exist_ok=True)
        (d / "env.sh").write_text("# written by `python -m ctf toolchain env --write` (B-188)\n" + text,
                                  encoding="utf-8")
        print(f"# wrote {d / 'env.sh'}", file=sys.stderr)
    return 0


def _envcheck(args) -> int:
    rep = _lanes.check(args.lane, root=args.root, python=args.python, pins=not args.no_pins)
    if args.json:
        print(json.dumps(rep.to_dict(), indent=1))
        return 0 if rep.passed else 1
    print(f"lane {rep.lane} env-check ({rep.python}):")
    for i in sorted(rep.items, key=lambda i: (i.ok, not i.required, i.kind, i.name)):
        if i.ok and not i.required:
            continue
        print("  " + i.line().replace("\n", "\n  "))
    n_ok = sum(1 for i in rep.items if i.ok)
    print(f"  ({n_ok}/{len(rep.items)} ok; optional ones that are present are not listed)")
    if rep.image:
        print(f"  tools the host lacks: image {rep.image!r} (`python -m ctf toolchain status --only {rep.image}`)")
    print("ENVCHECK " + ("OK" if rep.passed else "MISSING: " + ", ".join(i.name for i in rep.problems())))
    return 0 if rep.passed else 1


def _versions_cmd(args) -> int:
    try:
        sc = _versions.scan(Path(args.dir))
    except FileNotFoundError as e:
        return _err(str(e))
    imgs = _images.load(_images.manifest_path(args.root))
    picks = _versions.pick(sc.notes, imgs)
    mism = _versions.py_mismatches(sc.notes)
    bad = [p for p in picks if p.status in ("missing", "conflict")]
    if args.json:
        print(json.dumps({"files": sc.files, "truncated": sc.truncated, "skipped": list(sc.skipped),
                          "notes": [n.to_dict() for n in sc.notes], "picks": [p.to_dict() for p in picks],
                          "py_mismatches": [{"note": n.to_dict(), "installed": h} for n, h in mism]}, indent=1))
        return 1 if bad else 0
    print(f"version notes in {args.dir} ({sc.files} file(s) read"
          + (", TRUNCATED at the file cap" if sc.truncated else "") + "):")
    for n in sc.notes:
        where = f"{n.path}:{n.line}" if n.line else n.path
        print(f"  {n.tool:<14} {n.version:<10} {where}  {n.text!r}")
    for n, have in mism:
        print(f"  venv: {n.tool[3:]} is {have or 'not installed'}, the challenge pins {n.version} ({n.path})")
    by = {i.name: i for i in imgs}
    for p in picks:
        print(f"{p.status.upper():<9} {p.tool}: " + (f"{p.tag} — " if p.tag else "") + p.reason)
        if p.image:
            print("    run: " + " ".join(_images.run_argv(by[p.image], [p.tool, "<script>"], workdir=Path("."))))
    return 1 if bad else 0


def _wheels_cmd(args) -> int:
    d = Path(args.dir) if args.dir else None
    req = _wheels.requirements_path(args.root)
    if args.plan:
        for argv in _wheels.plan(d, req):
            print(" ".join(argv))
        return 0
    rep = _wheels.check(d, req)
    if args.json:
        print(json.dumps(rep.to_dict(), indent=1))
    else:
        print(f"wheelhouse {rep.directory}: {len(rep.present)}/{rep.pins} pins of {rep.requirements}")
        for name, ver in rep.missing[:50]:
            print(f"  MISSING {name}=={ver}")
        if len(rep.missing) > 50:
            print(f"  ... and {len(rep.missing) - 50} more")
        for name, ver, found in rep.other_version:
            print(f"  (has {name} {found}, not {ver})")
        print("WHEELS " + ("OK" if rep.passed else f"MISSING {len(rep.missing)} (`--plan` prints the fill command)"))
    return 0 if rep.passed else 1


_CMDS = {"lint": _lint, "status": _status, "build": _build, "smoke": _smoke, "assets": _assets_cmd,
         "env": _env, "envcheck": _envcheck, "versions": _versions_cmd, "wheels": _wheels_cmd}


def run(args: argparse.Namespace) -> int:
    try:
        return _CMDS[args.toolchain_cmd](args)
    except (_images.ImagesError, _assets.AssetsError, _lanes.LaneError, _wheels.WheelsError) as e:
        return _err(str(e))
