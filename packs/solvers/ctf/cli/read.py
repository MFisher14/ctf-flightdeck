"""ctf read — a targeted, capped, map-aware file read (B-034; binary-first and --symbol: B-199).

The reading rule, in code: cap output so a result is not re-read in full on every later model turn,
refuse a whole-file window (prefer --lines or --grep), and record the read in the challenge's shared
map so a second agent sees the first agent already read the same thing.

    python -m ctf read PATH --lines 10-40          a bounded range
    python -m ctf read PATH --grep PATTERN          targeted content query (with --around N context)
    python -m ctf read PATH --full                  the whole file (still capped unless --no-cap)
    python -m ctf read PATH --bytes N               a hex preview of the first N bytes (capped too)
    python -m ctf read PATH --symbol NAME           one Python def/class (ctf.symindex), whole and capped
    python -m ctf read BINARY                       binary-first: type, size, hash, entropy, hex head and
                                                    strings with offsets (ctf.binsummary), never a dump
    python -m ctf read PATH --strings [MIN]         every printable string (>= MIN chars, default 4) with
                                                    its offset, ascii then utf-16le (capped too)

--lines, --grep, --bytes, --symbol and --strings are one selection each (argparse refuses two). With
--map DIR, PATH must lie under DIR (the map keys a file by its path there). A binary file read with no
selection gets the summary (recorded as selector "summary"); --lines or --symbol on a binary is
refused (exit 1) in favour of --strings / --bytes. A --symbol read is recorded as its line range, so it
overlaps other line reads of the same lines in the shared map.

Refused (exit 4), before the file is opened: a symbolic link; a path that is or resolves into a
credentials folder (sweep.SECRET_DIRS: .ctf/, .git/); a .env / .env.* file outside a pulled challenge's
files/ (the platform's download there is challenge data, as in the sweep); and any path the read fence
denies (ctf.fence.read_fence: ~/.codex, ~/.claude, ~/.ssh, the repo's analysis/ and the other deny
roots, the event's fence.toml on top). Names are compared case-folded: the default macOS volume is
case-insensitive, so ~/.CODEX/auth.json is ~/.codex/auth.json.

Exit codes: 0 ok; 1 refused a whole-file/large window, or a line/symbol read of a binary (re-run with
--full/--grep/--strings/--bytes); 2 error (no such file, unreadable, a bad --lines/--grep/--bytes/
--strings/--map, two selections, a PATH outside --map DIR, a range past the end of the file, a
--symbol that is not found, is ambiguous or is read from a file that does not parse, a map that cannot
be read or written, a bad fence config); 4 refused a secret-bearing path.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import os
import re
import sys
from dataclasses import replace
from pathlib import Path

from .. import binsummary, env, hygiene, paths, symindex
from .. import fence as _fence
from .. import readmap as _readmap
from .. import sweep as _sweep

HELP = "read a file with output capped and whole-file windows refused (shared read map; B-034)"

REFUSED_EXIT = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("path", help="the file to read")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--lines", metavar="A-B", help="a line range: 10-40, 10- , -40, or a single 120")
    g.add_argument("--grep", metavar="PATTERN", help="show only lines matching this regex (targeted)")
    p.add_argument("--around", type=int, default=2, metavar="N", help="context lines around a --grep match")
    p.add_argument("--max-tokens", type=int, default=hygiene.CAP_TOKENS,
                   help=f"cap output to this many estimated tokens (default {hygiene.CAP_TOKENS})")
    p.add_argument("--max-lines", type=int, default=None, help="also cap output to this many lines")
    p.add_argument("--full", action="store_true", help="allow a whole-file/large window")
    p.add_argument("--no-cap", action="store_true", help="do not cap the output (prints all of it)")
    g.add_argument("--bytes", type=int, default=None, metavar="N",
                   help="show the first N bytes as a hex preview (for binary files; capped like text; "
                        "not with --lines or --grep)")
    g.add_argument("--symbol", metavar="NAME", default=None,
                   help="read one Python def or class by name (Cls.method for a method; see ctf symbols)")
    g.add_argument("--strings", type=int, nargs="?", const=4, default=None, metavar="MIN",
                   help="list every printable string of at least MIN chars (default 4) with its offset")
    p.add_argument("--map", metavar="DIR", default=None,
                   help="the challenge dir whose recon/readmap.json to use (else inferred from PATH)")
    p.add_argument("--no-map", action="store_true", help="do not read or update the shared read map")
    p.add_argument("--agent", default=None, help="agent id for the map (else $CTF_AGENT, else 'agent')")


def _err(msg: str, code: int) -> int:
    print(f"ctf read: {msg}", file=sys.stderr)
    return code


# ---------------------------------------------------------------- what may never be read

def _in_pulled_files(real: Path) -> bool:
    """`real` lies under `<challenge>/files/` of a pulled challenge (challenge.json beside files/)."""
    for d in real.parents:
        if d.name == "files" and (d.parent / "challenge.json").is_file():
            return True
    return False


def _fold(p: Path | None) -> Path | None:
    return None if p is None else Path(str(p).casefold())


def _folded(f: _fence.Fence) -> _fence.Fence:
    """`f` with every root, rule and name case-folded. The default macOS volume (APFS) is
    case-insensitive and Path.resolve() keeps the case it was given, so ~/.CODEX/auth.json opens
    ~/.codex/auth.json: a folded path is checked against folded rules. On a case-sensitive volume
    this refuses a little more (a real `.Git/` folder), never less."""
    return replace(
        f, repo=_fold(f.repo), workspace=_fold(f.workspace), home=_fold(f.home), drop=_fold(f.drop),
        extra_read=tuple(_fold(p) for p in f.extra_read), toolchain=tuple(_fold(p) for p in f.toolchain),
        deny=tuple(replace(d, path=_fold(d.path), carved_from=_fold(d.carved_from)) for d in f.deny),
        deny_names=tuple(replace(n, name=n.name.casefold()) for n in f.deny_names))


def _deny_fence() -> _fence.Fence:
    """The read fence (ctf.fence.read_fence: its deny rules, the current event's fence.toml on top),
    so `ctf read` refuses what a fenced agent could not read; case-folded (see _folded)."""
    slug = env.get("CTF_EVENT")
    ws = paths.workdir(slug) if slug else None    # strict_home only comes from an event's fence.toml
    return _folded(_fence.read_fence(_fence.load_config(slug), workspace=ws))


def _refusal(given: Path) -> str | None:
    """Why `given` may not be read (a secret-bearing or fence-denied path), or None. Names are
    compared case-folded (see _folded)."""
    if given.is_symlink():
        return f"{given} is a symbolic link; ctf read never follows one (read its target by its own path)"
    real = given.resolve()                       # also follows a link in a parent folder
    secret_dirs = {d.casefold(): d for d in _sweep.SECRET_DIRS}
    for p in (given.absolute(), real):
        hit = next((secret_dirs[x.casefold()] for x in p.parts if x.casefold() in secret_dirs), None)
        if hit:
            return f"{p} is or lies in a credentials folder ({hit}/)"
    if _sweep._secret_file(real.name.casefold()) and not _in_pulled_files(real):
        return f"{real} is a .env file outside a pulled challenge's files/ (may hold credentials)"
    v = _deny_fence().classify(_fold(_fence.canon(real)))
    if v is not None and v.kind == "denied":
        return f"{real} is in a store the read fence denies ({v.category}: {v.root})"
    return None


# ---------------------------------------------------------------- selections

def _parse_lines(spec: str, total: int) -> tuple[int, int]:
    """1-based inclusive (start, end) from 'A-B' | 'A-' | '-B' | 'A', the end clamped to the file.
    ValueError for a malformed or empty range, or a start past the last line."""
    spec = spec.strip()
    if "-" not in spec:
        start = end = int(spec)
    else:
        a, _, b = spec.partition("-")
        start = int(a) if a.strip() else 1
        end = int(b) if b.strip() else total
    if start > total and start >= 1:
        raise ValueError(f"line range {spec!r} starts past the end of the file ({total} lines)")
    if start < 1 or end < start:
        raise ValueError(f"bad line range {spec!r}")
    return start, min(end, total)


def _grep(lines: list[str], rx: re.Pattern, around: int) -> tuple[str, int]:
    """Matching lines with `around` context, with '--' between non-adjacent groups. (text, match count)."""
    keep: set[int] = set()
    matches = 0
    for i, ln in enumerate(lines):
        if rx.search(ln):
            matches += 1
            for j in range(max(0, i - around), min(len(lines), i + around + 1)):
                keep.add(j)
    out: list[str] = []
    prev = None
    for i in sorted(keep):
        if prev is not None and i != prev + 1:
            out.append("--")
        out.append(f"{i + 1}:{lines[i]}")
        prev = i
    return "\n".join(out), matches


def _lines_of(text: str) -> list[str]:
    """The file's lines: split on newline, without the empty piece a final newline leaves."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _challenge_dir(path: Path, given: str | None) -> Path | None:
    if given:
        return Path(given)
    path = path.resolve()            # the dir that holds the file itself (a linked parent is followed)
    for d in path.parents:
        if (d / "challenge.json").exists() or (d / "recon").is_dir():
            return d
    return None


def _hexpreview(data: bytes, n: int) -> str:
    return binsummary.hexdump(data, n)


def _strings_body(raw: bytes, min_len: int) -> str:
    found = binsummary.strings(raw, min_len=min_len)
    cut = (f" in the first {binsummary.SCAN_BYTES} of {len(raw)} bytes"
           if len(raw) > binsummary.SCAN_BYTES else "")
    out = [f"{len(found)} string(s) of >= {min_len} chars{cut} (ascii, then utf-16le):"]
    for off, enc, text in found:
        out.append(f"0x{off:08x}{'' if enc == 'ascii' else ' [utf16le]'}  {text}")
    return "\n".join(out)


def _symbol_window(raw: bytes, name: str) -> tuple[int, int]:
    """(start, end) lines of the one definition `name` means in this Python source. ValueError (the
    message lists the candidates) when it does not parse, matches nothing, or matches more than one."""
    try:
        syms = symindex.symbols_of(raw.decode("utf-8", "replace"))
    except symindex.SymbolError as e:
        raise ValueError(f"--symbol needs Python source: {e}") from None
    hits = symindex.lookup(syms, name)
    if not hits:
        tops = [s.name for s in syms if "." not in s.name and s.kind != "const"]
        more = f" (+{len(tops) - 30} more)" if len(tops) > 30 else ""
        raise ValueError(f"no symbol {name!r}; top-level defs and classes: {', '.join(tops[:30]) or '-'}"
                         f"{more} (`ctf symbols PATH` lists all)")
    if len(hits) > 1:
        raise ValueError(f"--symbol {name!r} is ambiguous: "
                         + ", ".join(f"{s.name} (L{s.start}-{s.end})" for s in hits)
                         + "; pass the qualified name")
    return hits[0].start, hits[0].end


def _read_file(path: Path) -> bytes:
    """The bytes of `path`, opened without following a link (a link swapped in after the check fails)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


# ---------------------------------------------------------------- the command

def run(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    try:
        why = _refusal(path)
    except _fence.FenceError as e:
        return _err(f"cannot check {path} against the read fence: {e}", 2)
    if why:
        return _err(f"refused: {why}", REFUSED_EXIT)
    symbol = getattr(args, "symbol", None)          # B-199 options: a hand-built Namespace may lack them
    strings_min = getattr(args, "strings", None)
    chosen = [n for n, v in (("--lines", args.lines), ("--grep", args.grep), ("--bytes", args.bytes),
                             ("--symbol", symbol), ("--strings", strings_min)) if v is not None and v != ""]
    if len(chosen) > 1:
        # argparse refuses the combination; this catches a caller that builds the Namespace itself
        return _err(f"{' and '.join(chosen)} cannot be combined (pick one selection)", 2)
    if args.map is not None and not args.no_map:
        mdir = Path(args.map).expanduser()
        if not mdir.is_dir():
            return _err(f"--map {args.map}: not a directory (pass the challenge dir, or --no-map)", 2)
        try:
            path.resolve().relative_to(mdir.resolve())
        except ValueError:
            return _err(f"{path} is not inside --map {args.map}; the map keys a file by its path under "
                        f"the challenge dir (pass that dir, or --no-map)", 2)
    try:
        raw = _read_file(path)
    except FileNotFoundError:
        return _err(f"no such file: {path}", 2)
    except OSError as e:
        if e.errno == errno.ELOOP:
            return _err(f"refused: {path} became a symbolic link", REFUSED_EXIT)
        return _err(f"cannot read {path}: {e}", 2)

    sha = hashlib.sha256(raw).hexdigest()

    # Binary files: a hex preview on request, otherwise a one-line summary and a refusal to flood.
    if args.bytes is not None:
        if args.bytes <= 0:
            return _err(f"--bytes must be positive, got {args.bytes}", 2)
        body = _hexpreview(raw, args.bytes)
        selector, kind = f"bytes:{args.bytes}", "binary"
    elif strings_min is not None:
        if strings_min < 1:
            return _err(f"--strings MIN must be at least 1, got {strings_min}", 2)
        body = _strings_body(raw, strings_min)
        selector = f"strings:{strings_min}"
        kind = "binary" if hygiene.looks_binary(raw) else "text"
    elif hygiene.looks_binary(raw) and not args.grep:
        if args.lines or symbol:
            return _err(f"refused: {path} is binary ({len(raw)} bytes); a line or symbol read of it is "
                        f"noise. Read it with no selection (the summary), --strings or --bytes N", 1)
        body = binsummary.summarize(path.name, raw).render()
        selector, kind = "summary", "binary"
    else:
        kind = "text"
        lines = _lines_of(raw.decode("utf-8", "replace"))
        total = len(lines)
        if args.grep:
            try:
                rx = re.compile(args.grep)
            except re.error as e:
                return _err(f"bad --grep pattern {args.grep!r}: {e}", 2)
            body, matches = _grep(lines, rx, max(args.around, 0))
            selector = f"grep:{args.grep}"
            if matches == 0:
                print(f"ctf read: no line matches {args.grep!r} in {path}", file=sys.stderr)
        elif symbol:
            try:
                start, end = _symbol_window(raw, symbol)
            except ValueError as e:
                return _err(str(e), 2)
            end = min(end, total)
            # a definition is a targeted read whatever its length: no window refusal, the cap still applies
            body = "\n".join(f"{i}:{lines[i - 1]}" for i in range(start, end + 1))
            selector = f"lines:{start}-{end}"
        elif args.lines:
            try:
                start, end = _parse_lines(args.lines, total)
            except ValueError as e:
                return _err(str(e), 2)
            n = end - start + 1
            adv = hygiene.window_advice(n, query=False)
            if not adv.ok and not args.full:
                return _err(f"refused: {adv.reason}; {adv.suggestion} (or --full)", 1)
            body = "\n".join(f"{i}:{lines[i - 1]}" for i in range(start, end + 1))
            selector = f"lines:{start}-{end}"
        else:
            adv = hygiene.window_advice(total, query=False)
            if not adv.ok and not args.full:
                return _err(f"refused: {adv.reason}; {adv.suggestion} (or --full)", 1)
            body = "\n".join(f"{i + 1}:{ln}" for i, ln in enumerate(lines))
            selector = "full"

    if args.no_cap:
        shown = body
        shown_tokens = hygiene.estimate_tokens(body)
    else:
        try:
            cap = hygiene.cap_text(body, max_tokens=args.max_tokens, max_lines=args.max_lines)
        except hygiene.HygieneError as e:
            return _err(str(e), 2)
        shown = cap.render()
        shown_tokens = cap.shown_tokens

    try:
        notes = _update_map(args, path, sha, len(raw), kind, selector, shown_tokens)
    except _readmap.ReadMapError as e:
        return _err(f"shared read map unavailable: {e} (fix or remove it, or pass --no-map)", 2)
    for note in notes:
        print(note)
    if body:
        print(shown)
    return 0


def _update_map(args: argparse.Namespace, path: Path, sha: str, size: int, kind: str,
                selector: str, tokens: int) -> list[str]:
    """Record the read in the shared map; return notes for reads of this content already made (by
    another agent, or by this one). ReadMapError propagates: the caller fails loudly."""
    if args.no_map:
        return []
    cdir = _challenge_dir(path, args.map)
    if cdir is None:
        print(f"ctf read: no challenge dir above {path} (no challenge.json or recon/); the read is not "
              f"recorded in a shared map (pass --map DIR, or --no-map)", file=sys.stderr)
        return []
    # run() refused a PATH outside --map DIR, and an inferred dir is one of PATH's parents
    rel = path.resolve().relative_to(cdir.expanduser().resolve()).as_posix()
    agent = args.agent or _readmap.agent_id()
    m = _readmap.ReadMap.open(cdir)
    prior = m.prior_reads(rel, selector, sha256=sha)
    owner = {id(r): e.path for e in m.entries.values() for r in e.reads}

    def what(p: _readmap.FileRead) -> str:
        at = owner.get(id(p), rel)
        same = p.selector == selector
        return (f"{'' if at == rel else f'the same bytes as {at}, '}{p.selector}"
                f"{'' if same else ', overlapping'}")

    m.record(rel, sha, size, kind, selector, tokens=tokens, agent=agent)
    m.save()
    where = cdir / _readmap.MAP_PATH
    others = [p for p in prior if p.agent != agent]
    mine = [p for p in prior if p.agent == agent]
    notes = []
    if others:
        p = others[0]
        notes.append(f"[ctf: {rel} ({selector}) was already read by {p.agent} ({what(p)}); see {where}]")
    if mine:
        p = mine[-1]
        notes.append(f"[ctf: you ({agent}) already read {rel} ({what(p)}) and it has not changed since]")
    return notes
