"""ctf symbols — a module's outline, or where a name is defined (B-199, ctf.symindex).

    python -m ctf symbols PATH|MODULE          imports, importers, every def/class/constant with lines
    python -m ctf symbols --find NAME          every definition of NAME across the repo (Cls.method works)
    python -m ctf symbols PATH --no-users      skip the importers (the slowest part on a cold cache)

PATH is a repo file (or a dotted module, `ctf.cli.read`). A Python file outside the repo (a challenge's
source) gets its outline from a direct parse, with no import graph, after the same refusal checks as
`ctf read` (secret folders, .env, the read fence). The output is capped like `ctf read`.

The index is cached under the gate's state folder ($CTF_GATE_STATE, else <git common dir>/ctf-gate;
`--state DIR` overrides), keyed by content hash, so only changed files are re-parsed.

Exit codes: 0 ok; 1 --find matched nothing; 2 error (not a Python file, an ambiguous module, no gate
config, a file that does not parse: a repo file's outline is still printed, with its parse error);
4 refused a secret-bearing or fence-denied path.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import hygiene, paths, symindex
from ..gate import GateError
from . import read as _read

HELP = "outline a module (defs with line ranges, imports, importers) or find where a name is defined (B-199)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", nargs="?", help="a repo .py file or dotted module (or a .py file outside the repo)")
    p.add_argument("--find", metavar="NAME", help="list every definition of NAME (a name, or Cls.method)")
    p.add_argument("--no-users", action="store_true", help="do not list the files that import it")
    p.add_argument("--max-tokens", type=int, default=hygiene.CAP_TOKENS,
                   help=f"cap output to this many estimated tokens (default {hygiene.CAP_TOKENS})")
    p.add_argument("--no-cap", action="store_true", help="do not cap the output")
    p.add_argument("--root", type=Path, default=None, help="the checkout (default: this repo)")
    p.add_argument("--state", type=Path, default=None, help="cache folder (default: the gate's state folder)")


def _err(msg: str, code: int) -> int:
    print(f"ctf symbols: {msg}", file=sys.stderr)
    return code


def _show(text: str, args) -> None:
    if args.no_cap:
        print(text)
        return
    print(hygiene.cap_text(text, max_tokens=args.max_tokens).render())


def _outside(path: Path, args) -> int:
    """Outline a Python file outside the checkout: a direct parse, no graph, no cache."""
    try:
        why = _read._refusal(path)
    except _read._fence.FenceError as e:
        return _err(f"cannot check {path} against the read fence: {e}", 2)
    if why:
        return _err(f"refused: {why}", _read.REFUSED_EXIT)
    try:
        text = _read._read_file(path).decode("utf-8", "replace")
    except OSError as e:
        return _err(f"cannot read {path}: {e}", 2)
    try:
        syms = symindex.symbols_of(text)
    except symindex.SymbolError as e:
        return _err(f"{path}: {e}", 2)
    out = [f"{path}: {len(text.splitlines())} lines, {len(syms)} symbols (outside the repo: no import graph)"]
    out += [symindex.format_symbol(s) for s in syms]
    out.append(f"[ctf: read one with `python -m ctf read {path} --symbol NAME`]")
    _show("\n".join(out), args)
    return 0


def run(args: argparse.Namespace) -> int:
    if bool(args.target) == bool(args.find):
        return _err("give a TARGET to outline or --find NAME (one of them)", 2)
    if args.max_tokens <= 0:
        return _err(f"--max-tokens must be positive, got {args.max_tokens}", 2)
    root = (args.root or paths.repo_root()).resolve()
    if args.target:
        cand = Path(args.target).expanduser()
        absolute = cand if cand.is_absolute() else Path.cwd() / cand
        if absolute.exists():
            try:
                absolute.resolve().relative_to(root)
            except ValueError:
                return _outside(absolute, args)
    try:
        state = args.state.resolve() if args.state else paths.gate_state(root)
        idx = symindex.SymbolIndex(root, state)
    except (GateError, FileNotFoundError) as e:
        return _err(f"cannot build the symbol index: {e}", 2)
    if idx.stats.rebuilt:
        print(f"ctf symbols: {idx.stats.rebuilt}", file=sys.stderr)
    if args.find:
        hits = idx.find(args.find)
        if not hits:
            return _err(f"no definition of {args.find!r} in {len(idx.py_files)} indexed Python files", 1)
        _show("\n".join(f"{rel}:{s.start}-{s.end}  {s.kind} {s.name}{s.signature}" for rel, s in hits), args)
        return 0
    try:
        rel = idx.resolve(args.target)
    except symindex.SymbolError as e:
        return _err(str(e), 2)
    _show(idx.outline(rel, users=not args.no_users), args)
    if idx.error(rel):
        # the outline (with its "parse error:" line) is still printed: imports/importers come from the
        # gate graph; but the symbol list is empty or partial, so the exit says the file did not parse
        return _err(f"{rel} does not parse: {idx.error(rel)}", 2)
    return 0
