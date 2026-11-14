#!/usr/bin/env python3
"""One install source for the Python dependencies (R-14).

`requirements.in` is the only file a person edits. Every line in it is an exact pin (`name==version`),
a comment or a blank line. `requirements.txt` is generated from it with every pin and nothing else, and
it is the one file `setup.sh` installs. `requirements.lock.txt` is the frozen .venv the suite was
validated against; it may list transitive packages and may lag new pins, but it may never pin a
package that requirements.in also pins at another version.

  .venv/bin/python tools/requirements_gen.py            write requirements.txt from requirements.in
  .venv/bin/python tools/requirements_gen.py --check    exit 1, naming each problem, when requirements.txt
                                                        is stale, the lock contradicts a pin, or setup.sh
                                                        installs anything but requirements.txt (pip/uv
                                                        install and sync, pip-sync: -r/--requirements,
                                                        -c/--constraints, --overrides, --excludes,
                                                        --group, -e/--editable, bare packages; the
                                                        UV_CONSTRAINT, UV_OVERRIDE, PIP_CONSTRAINT,
                                                        PIP_REQUIREMENT and PIP_EDITABLE variables; an
                                                        installer named by a variable, `$PIP install`)
  --root DIR                                            another checkout (default: this one)

Exit 0 when fine, 1 on a problem, 2 on a usage error or an invalid requirements.in.

Rejected in requirements.in (each fails loudly with its line number): a range or unpinned spec, an
option line (`-r`, `-c`, `--index-url`, ...), a URL or path requirement, an environment marker, and a
package pinned twice (even at the same version).
"""
from __future__ import annotations

import argparse
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SOURCE = "requirements.in"
TARGET = "requirements.txt"
LOCK = "requirements.lock.txt"
SETUP = "setup.sh"

HEADER = (
    "# GENERATED from requirements.in by tools/requirements_gen.py. Do not edit: edit requirements.in,\n"
    "# then run `.venv/bin/python tools/requirements_gen.py`. setup.sh installs this file:\n"
    "#   uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -r requirements.txt\n"
)

_PIN = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)$")
_SECTION = re.compile(r"^#\s*---")


class RequirementsError(ValueError):
    """requirements.in holds a line that is not an exact pin, or pins a package twice."""


@dataclass(frozen=True)
class Pin:
    name: str
    version: str
    lineno: int

    @property
    def key(self) -> str:
        return canon(self.name)


def canon(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pins(text: str, source: str = SOURCE) -> list[Pin]:
    """Every pin of a strict requirements file, in order. Raises RequirementsError naming the line."""
    pins: list[Pin] = []
    seen: dict[str, Pin] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        spec = re.split(r"\s+#", line, 1)[0].strip()
        m = _PIN.match(spec)
        if not m:
            raise RequirementsError(
                f"{source}:{n}: {spec!r} is not an exact pin (name==version); "
                "ranges, options, URLs, paths and markers are not allowed")
        pin = Pin(m.group(1), m.group(2), n)
        if pin.key in seen:
            first = seen[pin.key]
            raise RequirementsError(
                f"{source}:{n}: {pin.name} is pinned twice ({first.name}=={first.version} at line "
                f"{first.lineno}, {pin.name}=={pin.version} here); keep one line")
        seen[pin.key] = pin
        pins.append(pin)
    return pins


def read_lock(text: str) -> dict[str, str]:
    """The pins of a freeze-style lock file (comments, options and other lines are ignored)."""
    out = {}
    for raw in text.splitlines():
        m = _PIN.match(re.split(r"\s+#", raw.strip(), 1)[0].strip())
        if m:
            out[canon(m.group(1))] = m.group(2)
    return out


def render(in_text: str) -> str:
    """requirements.txt for this requirements.in: the header, the section titles, every pin."""
    pins = {p.lineno: p for p in parse_pins(in_text)}
    out = [HEADER.rstrip("\n")]
    for n, raw in enumerate(in_text.splitlines(), 1):
        line = raw.strip()
        if n in pins:
            out.append(f"{pins[n].name}=={pins[n].version}")
        elif _SECTION.match(line):
            out += ["", line]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------- what setup.sh installs
@dataclass
class Install:
    """One `pip install` / `uv pip install` / `uv pip sync` / `pip-sync` command found in a shell script."""
    lineno: int
    command: str
    files: list[str] = field(default_factory=list)        # -r / --requirement(s); a sync's file arguments
    constraints: list[str] = field(default_factory=list)  # -c / --constraint(s)
    specs: list[str] = field(default_factory=list)        # bare package arguments (and -e targets)
    others: list[str] = field(default_factory=list)       # other install sources, e.g. "--overrides o.txt"
    guarded: bool = False                                 # followed by `||`: a failure is swallowed
    kind: str = "install"                                 # "install" or "sync"


# Options of pip / uv pip install and sync that take a value and do not choose what is installed. Any
# other option is treated as a flag.
_VALUED = {"-p", "--python", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
           "--target", "--prefix", "--root", "--python-version", "--python-platform", "--cache-dir",
           "--index", "--default-index", "--index-strategy", "--keyring-provider", "--resolution",
           "--prerelease", "--exclude-newer", "--config-settings", "-C", "--src", "--upgrade-package",
           "-P", "--reinstall-package", "--no-binary", "--only-binary", "--build-constraints", "-b",
           "--extra", "--python-executable"}

# Options that choose what is installed: (option, Install field its value goes to). Long forms also take
# `--opt=value`, short forms `-rvalue`. uv spells them plural (--requirements), pip singular.
_SOURCE_FLAGS = (("-r", "files"), ("--requirement", "files"), ("--requirements", "files"),
                 ("-c", "constraints"), ("--constraint", "constraints"), ("--constraints", "constraints"),
                 ("--override", "others"), ("--overrides", "others"), ("--excludes", "others"),
                 ("--group", "others"), ("-e", "specs"), ("--editable", "specs"))
_TAGS = {"-e": "-e ", "--editable": "-e "}  # how a value is recorded; an "others" value keeps its option

# Environment variables that make pip or uv install from another file. Set as a command prefix
# (`UV_CONSTRAINT=c.txt uv pip install ...`) or exported for later commands (`export PIP_CONSTRAINT=...`).
# UV_BUILD_CONSTRAINT is left out for the reason --build-constraints is a valued option.
_ENV_SOURCES = {"UV_CONSTRAINT", "UV_OVERRIDE", "PIP_CONSTRAINT", "PIP_REQUIREMENT", "PIP_EDITABLE"}
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")
_DECLARERS = {"export", "env", "declare", "typeset", "readonly", "local"}

_SHELL_OPS = ";&|()"


def _logical_lines(text: str):
    """(first line number, text) of each logical line: backslash continuations joined, comments cut."""
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        buf += raw
        yield start, buf
        buf = ""
    if buf:
        yield start, buf


def _tokens(line: str) -> list[str]:
    lex = shlex.shlex(line, posix=True, punctuation_chars=_SHELL_OPS)
    lex.whitespace_split = True
    lex.commenters = "#"
    return list(lex)


def _installer(cmd: list[str]) -> tuple[str, int] | None:
    """(kind, index of its first argument) when `cmd` is a pip install or a pip sync, else None."""
    for i, tok in enumerate(cmd):
        name = Path(tok).name
        if name == "pip-sync":
            return "sync", i + 1
        if re.fullmatch(r"pip3?(\.\d+)?", name) and i + 1 < len(cmd) and cmd[i + 1] in ("install", "sync"):
            return cmd[i + 1], i + 2
    return None


def _commands(text: str):
    """(line number, words, the shell operator after it) of each simple command in a shell script."""
    for lineno, line in _logical_lines(text):
        try:
            toks = _tokens(line)
        except ValueError as e:
            raise RequirementsError(f"{SETUP}:{lineno}: cannot parse shell line ({e})") from None
        cmds, cur, ops = [], [], []
        for t in toks:
            if t and set(t) <= set(_SHELL_OPS):
                cmds.append(cur)
                ops.append(t)
                cur = []
            else:
                cur.append(t)
        cmds.append(cur)
        ops.append("")
        for cmd, op in zip(cmds, ops):
            yield lineno, cmd, op


def setup_env_sources(text: str) -> list[tuple[int, str]]:
    """(line number, `NAME=value`) for each install-source environment variable a shell script sets: as a
    command prefix, or through export/env/declare/typeset/readonly/local, or as a plain assignment."""
    found = []
    for lineno, cmd, _ in _commands(text):
        i, declaring = 0, False
        while i < len(cmd):
            m = _ASSIGN.match(cmd[i])
            if m:
                if m.group(1) in _ENV_SOURCES:
                    found.append((lineno, cmd[i]))
            elif cmd[i] in _DECLARERS and not declaring:
                declaring = True
            elif not (declaring and cmd[i].startswith("-")):
                break
            i += 1
    return found


def setup_opaque_installs(text: str) -> list[tuple[int, str]]:
    """(line number, command) for each `$VAR install ...` / `$VAR sync ...`: an installer named by a
    variable, so the check cannot tell whether it is pip or what it installs."""
    found = []
    for lineno, cmd, _ in _commands(text):
        if _installer(cmd) is not None:
            continue
        for i, tok in enumerate(cmd[:-1]):
            if "$" in tok and cmd[i + 1] in ("install", "sync"):
                found.append((lineno, " ".join(cmd)))
                break
    return found


def setup_installs(text: str) -> list[Install]:
    """Every pip install / pip sync command in a shell script, with what it installs."""
    found = []
    for lineno, cmd, op in _commands(text):
        hit = _installer(cmd)
        if hit is None:
            continue
        kind, start = hit
        inst = Install(lineno, " ".join(cmd), guarded=op == "||", kind=kind)
        args, i = cmd[start:], 0
        while i < len(args):
            a = args[i]
            for flag, field_name in _SOURCE_FLAGS:
                bucket = getattr(inst, field_name)
                tag = flag + " " if field_name == "others" else _TAGS.get(flag, "")
                if a == flag:
                    if i + 1 >= len(args):
                        raise RequirementsError(f"{SETUP}:{lineno}: {flag} with no file")
                    bucket.append(tag + args[i + 1])
                    i += 1
                    break
                if flag.startswith("--") and a.startswith(flag + "="):
                    bucket.append(tag + a.split("=", 1)[1])
                    break
                if not flag.startswith("--") and a.startswith(flag) and len(a) > 2:
                    bucket.append(tag + a[2:])
                    break
            else:
                if a in _VALUED:
                    i += 1
                elif not a.startswith("-"):
                    # pip sync takes requirement files as arguments; pip install takes packages
                    (inst.files if kind == "sync" else inst.specs).append(a)
            i += 1
        found.append(inst)
    return found


def setup_problems(text: str) -> list[str]:
    """Why setup.sh does not install exactly requirements.txt, once, unguarded (empty when it does)."""
    out, installs = [], setup_installs(text)
    if not installs:
        return [f"{SETUP}: no pip install command; it must install -r {TARGET}"]
    for inst in installs:
        where = f"{SETUP}:{inst.lineno}"
        for f in inst.files:
            if f != TARGET:
                how = "syncs the venv to" if inst.kind == "sync" else "installs -r"
                out.append(f"{where}: {how} {f}; the one install source is {TARGET}")
        for s in inst.specs:
            out.append(f"{where}: installs {s!r} outside {TARGET}; pin it in {SOURCE} instead")
        for c in inst.constraints:
            out.append(f"{where}: uses constraint file {c}; {TARGET} is the one install source")
        for o in inst.others:
            out.append(f"{where}: uses {o}, another install source; {TARGET} is the one install source")
        if TARGET in inst.files and inst.guarded:
            out.append(f"{where}: the {TARGET} install is followed by `||`, so a failure is swallowed")
    for lineno, word in setup_env_sources(text):
        out.append(f"{SETUP}:{lineno}: sets {word}, another install source; {TARGET} is the one install source")
    for lineno, cmd in setup_opaque_installs(text):
        out.append(f"{SETUP}:{lineno}: runs {cmd!r}, an installer named by a variable, so the check cannot "
                   f"tell what it installs; call pip or uv by name")
    n = sum(inst.files.count(TARGET) for inst in installs)
    if n != 1:
        out.append(f"{SETUP}: installs -r {TARGET} {n} times; it must install it exactly once")
    return out


# ----------------------------------------------------------------------------------------------- the check
def check(root: Path) -> list[str]:
    """Every problem with the install source of the checkout at `root` (empty when it is consistent)."""
    problems = []
    src = root / SOURCE
    if not src.is_file():
        return [f"{SOURCE} is missing at {root}"]
    in_text = src.read_text()
    pins = parse_pins(in_text)
    want = render(in_text)
    tgt = root / TARGET
    if not tgt.is_file():
        problems.append(f"{TARGET} is missing; run tools/requirements_gen.py")
    elif tgt.read_text() != want:
        have = {p.key: p.version for p in parse_pins(tgt.read_text(), TARGET)} if _strict_ok(tgt) else None
        detail = ""
        if have is not None:
            need = {p.key: p.version for p in pins}
            diff = sorted(f"{k}: {have.get(k)} -> {need.get(k)}"
                          for k in set(have) | set(need) if have.get(k) != need.get(k))
            detail = ("; pins differ: " + ", ".join(diff[:12])) if diff else "; pins agree, text differs"
        problems.append(f"{TARGET} is stale against {SOURCE}{detail}; run tools/requirements_gen.py")
    lock = root / LOCK
    if not lock.is_file():
        problems.append(f"{LOCK} is missing at {root}")
    else:
        locked = read_lock(lock.read_text())
        for p in pins:
            if p.key in locked and locked[p.key] != p.version:
                problems.append(f"{LOCK} pins {p.name}=={locked[p.key]}, {SOURCE} pins =={p.version}")
    setup = root / SETUP
    if not setup.is_file():
        problems.append(f"{SETUP} is missing at {root}")
    else:
        problems += setup_problems(setup.read_text())
    return problems


def _strict_ok(path: Path) -> bool:
    try:
        parse_pins(path.read_text(), path.name)
        return True
    except RequirementsError:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=Path, default=REPO)
    ap.add_argument("--check", action="store_true", help="report problems, write nothing")
    args = ap.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.check:
            problems = check(root)
            for p in problems:
                print(f"FAIL {p}", file=sys.stderr)
            if not problems:
                print(f"ok: {TARGET} matches {SOURCE}, the lock agrees, setup.sh installs {TARGET} only")
            return 1 if problems else 0
        src = root / SOURCE
        if not src.is_file():
            print(f"FAIL {SOURCE} is missing at {root}", file=sys.stderr)
            return 2
        text = render(src.read_text())
        (root / TARGET).write_text(text)
        print(f"wrote {TARGET}: {len(parse_pins(text, TARGET))} pins")
        return 0
    except RequirementsError as e:
        print(f"FAIL {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
