"""ctf re-workbench -- the static-RE workbench (B-165).

Three offline sub-commands; none ever runs a challenge binary or touches the network:

  check               static-RE import readiness: capstone / unicorn / lief (tools/static_re_check.py's
                      checks, reused) plus pefile, with versions. Exit 0 ready, 1 not ready.
  scaffold <dir>      materialize a swarm workspace -- the template, an empty shared findings file,
                      a worked VMSpec, a captured readiness line, and the board's pinned
                      acceptance gate (one of --gate-digest / --gate-regex / --gate-flagfmt is
                      required; --gate-later opts out explicitly)
  findings <board>    read a findings board: all rows, or (--accepted) the gate-accepted rows
                      re-verified against the board's pinned gate; rows that do not re-verify are
                      flagged and the exit code is 1

The kit itself is imported from solvers/binary (re_workbench.py, vm_lifter.py) and tools/
(shared_findings.py, the swarm board); this command only sets it up and reads its output.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib
import json
import os
import sys
from pathlib import Path

from .. import packs, paths

HELP = "static-RE workbench: import readiness, scaffold a swarm workspace, read findings (B-165)"

# What the workbench needs beyond tools/static_re_check.py's REQUIRED table (capstone/unicorn/lief).
_EXTRA_READINESS = {"pefile": ("PE",)}

_TEMPLATE_DIR = "templates/static-re"
_STATIC_RE_CHECK = "tools/static_re_check.py"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="static-RE import readiness (capstone/unicorn/lief/pefile)")
    c.add_argument("--json", action="store_true", help="machine-readable output")

    s = sub.add_parser("scaffold", help="materialize a static-RE swarm workspace")
    s.add_argument("dir", help="workspace directory to create")
    s.add_argument("--challenge", default="(unnamed challenge)", help="challenge name for the brief")
    s.add_argument("--agents", type=int, default=4, help="racers the brief is written for")
    s.add_argument("--force", action="store_true", help="overwrite an existing, non-empty directory")
    # a gate is required: an ungated board would let the first racer pin any gate it likes
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--gate-digest", metavar="ALGO:HEX",
                   help="pin the gate: accept iff hash(candidate) == HEX (e.g. sha1:<40 hex>)")
    g.add_argument("--gate-regex", metavar="PATTERN", help="pin the gate: accept iff the candidate fully matches")
    g.add_argument("--gate-flagfmt", action="store_true",
                   help="pin the gate to the active event's flag format (CTF_EVENT / ctf.event.current())")
    g.add_argument("--gate-later", action="store_true",
                   help="pin no gate now (e.g. a predicate_gate a racer will write): the first board "
                        "opened with gate=... pins it, first come")

    f = sub.add_parser("findings", help="read a shared findings board")
    f.add_argument("board", help="path to a findings.jsonl board")
    f.add_argument("--accepted", action="store_true",
                   help="only gate-accepted findings, re-verified against the pinned gate")
    f.add_argument("--json", action="store_true", help="machine-readable output")


# ------------------------------------------------------------------------------------- check

def _load_static_re_check():
    return packs.load_module("re_workbench_static_re_check", paths.repo_root() / _STATIC_RE_CHECK,
                             pack="static_re_check")


def _inspect_readiness() -> tuple[dict[str, str], list[str]]:
    """tools/static_re_check.inspect() (capstone/unicorn/lief) plus the pefile check, one report."""
    src = _load_static_re_check()
    versions, problems = src.inspect(importlib.import_module)
    for name, attrs in _EXTRA_READINESS.items():
        try:
            mod = importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - report any import failure by name
            problems.append(f"{name}: import {type(exc).__name__}: {str(exc).splitlines()[0][:120]}")
            continue
        versions[name] = src.version(mod)
        missing = [a for a in attrs if not hasattr(mod, a)]
        if missing:
            problems.append(f"{name}: missing {','.join(missing)}")
    return versions, problems


def _readiness_line(versions: dict[str, str], problems: list[str]) -> str:
    if problems:
        return "STATIC_RE_READY FAIL " + " | ".join(problems)
    return "STATIC_RE_READY OK " + " ".join(f"{k}={versions[k]}" for k in sorted(versions))


def _run_check(args: argparse.Namespace) -> int:
    try:
        versions, problems = _inspect_readiness()
    except packs.PackError as exc:
        print(f"ctf re-workbench: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"ok": not problems, "versions": versions, "problems": problems}, sort_keys=True))
    else:
        print(_readiness_line(versions, problems))
    return 0 if not problems else 1


# ---------------------------------------------------------------------------------- scaffold

def _template_dir() -> Path:
    d = paths.repo_root() / _TEMPLATE_DIR
    if not d.is_dir():
        raise FileNotFoundError(f"static-RE template not found at {d} (expected {_TEMPLATE_DIR}/)")
    return d


def _render(text: str, mapping: dict[str, str]) -> str:
    for key, value in mapping.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def _gate_from_args(sf, args: argparse.Namespace):
    if args.gate_digest:
        algo, sep, hexd = args.gate_digest.partition(":")
        if not sep or not algo or not hexd:
            raise sf.FindingsError("--gate-digest wants ALGO:HEX (e.g. sha1:<hex digest>)")
        return sf.digest_gate(algo, hexd)
    if args.gate_regex is not None:
        return sf.regex_gate(args.gate_regex)
    if args.gate_flagfmt:
        return sf.flagfmt_gate()
    if getattr(args, "gate_later", False):
        return None
    raise sf.FindingsError("scaffold needs a gate: --gate-digest, --gate-regex, --gate-flagfmt or --gate-later")


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def _run_scaffold(args: argparse.Namespace) -> int:
    dest = Path(args.dir)
    if dest.exists() and any(dest.iterdir()) and not args.force:
        print(f"ctf re-workbench: {dest} exists and is not empty (use --force)", file=sys.stderr)
        return 2
    try:
        src = _template_dir()
        sf = _load_board_module()
        gate = _gate_from_args(sf, args)
    except FileNotFoundError as exc:
        print(f"ctf re-workbench: {exc}", file=sys.stderr)
        return 2
    except packs.PackError as exc:
        print(f"ctf re-workbench: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a bad gate (FindingsError) or no event (EventError), named
        print(f"ctf re-workbench: cannot build the gate: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    dest.mkdir(parents=True, exist_ok=True)
    repo = paths.repo_root()
    mapping = {
        "CHALLENGE": args.challenge,
        "AGENTS": str(args.agents),
        "CREATED": _dt.date.today().isoformat(),
        "REPO": str(repo),
        "GATE": gate.describe() if gate is not None else
                "none pinned yet (--gate-later: the first FindingsBoard opened with gate=... pins it)",
    }
    created: list[str] = []
    for item in sorted(src.iterdir()):
        if item.name.endswith(".tmpl"):
            out_name = item.name[: -len(".tmpl")]
            (dest / out_name).write_text(_render(item.read_text(encoding="utf-8"), mapping), encoding="utf-8")
            created.append(out_name)
        elif item.is_file():
            (dest / item.name).write_text(item.read_text(encoding="utf-8"), encoding="utf-8")
            created.append(item.name)
    # the shared findings file starts empty (owner-only: it will hold candidate flags)
    board_path = dest / "findings.jsonl"
    if not board_path.exists():
        _write_private(board_path, "")
    created.append("findings.jsonl")
    if gate is not None:
        try:
            sf.FindingsBoard(board_path, gate=gate)
        except sf.FindingsError as exc:      # --force over a board already pinned to another gate
            print(f"ctf re-workbench: {exc}", file=sys.stderr)
            return 2
        created.append(sf.gate_path(board_path).name)
    try:
        versions, problems = _inspect_readiness()
        readiness = _readiness_line(versions, problems)
    except packs.PackError as exc:
        problems = [str(exc)]
        readiness = f"STATIC_RE_READY FAIL {exc}"
    (dest / "readiness.txt").write_text(readiness + "\n", encoding="utf-8")
    created.append("readiness.txt")
    print(f"scaffolded static-RE workbench at {dest}")
    for name in created:
        print(f"  {name}")
    if gate is None:
        print("note: --gate-later: no acceptance gate pinned; accept() refuses until one is, and the "
              "first racer to open the board with a gate pins it (see README.md)", file=sys.stderr)
    if problems:
        print("note: static-RE readiness FAIL -- " + " | ".join(problems), file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------------- findings

def _load_board_module():
    path = paths.repo_root() / "tools" / "shared_findings.py"
    return packs.load_module("re_workbench_shared_findings", path, pack="shared_findings")


def _line(r, tag: str) -> str:
    line = f"[{tag}] {r.key} ({r.agent}) {r.kind}: {r.summary}"
    if r.candidate is not None:
        line += f"  candidate={r.candidate!r}"
    return line


def _run_findings(args: argparse.Namespace) -> int:
    board_path = Path(args.board)
    if not board_path.exists():
        print(f"ctf re-workbench: no findings board at {board_path}", file=sys.stderr)
        return 2
    try:
        sf = _load_board_module()
    except packs.PackError as exc:
        print(f"ctf re-workbench: {exc}", file=sys.stderr)
        return 2
    board = sf.FindingsBoard(board_path)
    try:
        if not args.accepted:
            rows = board.entries()
        else:
            gate = board.pinned_gate()
            verdicts = board.audit()
    except sf.FindingsError as exc:
        print(f"ctf re-workbench: {exc}", file=sys.stderr)
        return 2
    if not args.accepted:
        if args.json:
            print(json.dumps([r.to_dict() for r in rows]))
        elif not rows:
            print("(no findings)")
        else:
            for r in rows:
                print(_line(r, r.status))
        return 0

    ok = [v.finding for v in verdicts if v.ok]
    bad = [v for v in verdicts if not v.ok]
    if args.json:
        print(json.dumps({
            "gate": gate.to_dict() if gate is not None else None,
            "accepted": [r.to_dict() for r in ok],
            "flagged": [{"finding": v.finding.to_dict(), "reason": v.reason} for v in bad],
        }))
    else:
        print(f"gate: {gate.describe() if gate is not None else '(none pinned)'}")
        if not ok and not bad:
            print("(no accepted findings)")
        for r in ok:
            print(_line(r, "accepted"))
        for v in bad:
            print(_line(v.finding, "FLAGGED") + f"  -- {v.reason}")
    if bad:
        print(f"ctf re-workbench: {len(bad)} accepted-status row(s) do not re-verify against the "
              "pinned gate; do not submit them", file=sys.stderr)
        return 1
    return 0


def run(args: argparse.Namespace) -> int:
    if args.cmd == "check":
        return _run_check(args)
    if args.cmd == "scaffold":
        return _run_scaffold(args)
    if args.cmd == "findings":
        return _run_findings(args)
    raise AssertionError(f"unknown sub-command {args.cmd!r}")  # pragma: no cover - argparse guards
