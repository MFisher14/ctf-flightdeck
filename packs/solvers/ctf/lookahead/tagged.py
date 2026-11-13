"""Tagged-copy staging for the daily look-ahead (B-256): where a file's TAGGED copy lives, per language.

Huntress Day 18 (backlog row 355): the Script look-ahead staged 341 shapes, and every one kept the tagged
copy `<TAG>-<payload>` in a comment, beside an untagged copy of the payload. Day 18 moved the tagged copy
itself into a joined array behind a bare marker comment, and 55 ids went unanswered on the morning. The
retro asked that each look-ahead stage, per language family, where the tagged copy lives. The 2026 answer
was "fold it into the prompt"; here it is a no-model step, so it cannot be left out of a prompt:

    rs = render(family, container, tag, seed)       # Rendered: the file text, and how to read it back
    names = stage(matrix_dir, lane, tag, seed=..., families=None, containers=None)   # specimen folders

Containers (CONTAINERS), each beside an untagged copy of the payload in a second place:

    comment          the 2026 look-ahead shape: `<comment> <TAG>-<payload>`
    marker-joined    a bare `<comment> <TAG>:SPLIT` marker; the tagged copy is a joined array of pieces
    concat           a bare `<comment> <TAG>` marker; the tagged copy is a `+` (`.`, `..`) concatenation
    charcodes        a bare marker; the tagged copy is built from character codes
    property         a bare marker; the tagged copy is an object / dict / hash property
    heredoc          a bare marker; the tagged copy is a here-doc (or the language's long string)
    no-comment       no comment at all; the tagged copy is a plain string constant
    split-constants  a bare marker; the tagged copy is split over two constants joined where it is used

Families (FAMILIES): python, javascript, apps-script (.gs), powershell, bash, php, ruby, perl, lua.
`bash` has no `property` (macOS /bin/bash 3.2 has no associative arrays, so the shape could not be
proven by running it); `NOT_APPLICABLE` lists it and `stage` reports it, never silently.

Every rendered file is source we write ourselves (synthetic), never a challenge file. Each specimen is a
look-ahead matrix specimen (ctf.lookahead.matrix): encoding ["raw"], one deterministic question
`tagged_copy` (or `question_id`), key.json holding the full `<TAG>-<payload>`. The tag is the event's
(it is never built in here): a missing or malformed tag is a LookaheadError. Re-staging the same day
rewrites only folders this module staged (their specimen.toml note starts with STAGED_NOTE); any other
folder of the same name is refused.
"""
from __future__ import annotations

import json
import random
import re
import shutil
import string
from dataclasses import dataclass
from pathlib import Path

from . import LookaheadError
from . import matrix as _matrix

CONTAINERS = ("comment", "marker-joined", "concat", "charcodes", "property", "heredoc", "no-comment",
              "split-constants")
MARKER_CONTAINERS = ("marker-joined", "concat", "charcodes", "property", "heredoc", "split-constants")
STAGED_NOTE = "staged by ctf.lookahead.tagged (B-256)"
PREFIX = "tagged"
DEFAULT_QID = "tagged_copy"
_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_PAYLOAD_ALPHABET = string.ascii_letters + string.digits


@dataclass(frozen=True)
class Rendered:
    family: str
    container: str
    ext: str
    text: str
    tagged: str            # the full <TAG>-<payload> the file carries
    payload: str           # the untagged payload (also carried, in a second place)
    probe: str | None      # an expression of the family that evaluates to `tagged` (None: comment only)
    second: str            # an expression of the family that evaluates to the untagged `payload`
    comment: str           # the family's line-comment token


def _q(s: str) -> str:
    """A double-quoted literal. Tags and payloads are [A-Za-z0-9_-:], which need no escape anywhere."""
    return '"' + s + '"'


class _Family:
    name = ""
    ext = ""
    comment = "#"
    header: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()

    def assign(self, name: str, expr: str) -> str:
        return f"{name} = {expr}"

    def ref(self, name: str) -> str:
        return name

    def join(self, parts) -> str:
        raise NotImplementedError

    def concat(self, exprs) -> str:
        return " + ".join(exprs)

    def chars(self, codes) -> str:
        raise NotImplementedError

    def prop(self, obj: str, key: str, value: str) -> tuple[list[str], str]:
        raise NotImplementedError

    def heredoc(self, name: str, value: str) -> list[str]:
        raise NotImplementedError

    def print_stmt(self, expr: str) -> str:
        raise NotImplementedError


class _Python(_Family):
    name, ext = "python", ".py"

    def join(self, parts):
        return '"".join([' + ", ".join(_q(p) for p in parts) + "])"

    def chars(self, codes):
        return '"".join(map(chr, [' + ", ".join(map(str, codes)) + "]))"

    def prop(self, obj, key, value):
        return [f"{obj} = {{{_q(key)}: {_q(value)}}}"], f"{obj}[{_q(key)}]"

    def heredoc(self, name, value):
        return [f'{name} = """', value, '""".strip()']

    def print_stmt(self, expr):
        return f"print({expr})"


class _JavaScript(_Family):
    name, ext, comment = "javascript", ".js", "//"

    def assign(self, name, expr):
        return f"const {name} = {expr};"

    def join(self, parts):
        return "[" + ", ".join(_q(p) for p in parts) + '].join("")'

    def chars(self, codes):
        return "String.fromCharCode(" + ", ".join(map(str, codes)) + ")"

    def prop(self, obj, key, value):
        return [f"const {obj} = {{ {key}: {_q(value)} }};"], f"{obj}.{key}"

    def heredoc(self, name, value):
        return [f"const {name} = `", value, "`.trim();"]

    def print_stmt(self, expr):
        return f"console.log({expr});"


class _AppsScript(_JavaScript):
    name, ext = "apps-script", ".gs"


class _PowerShell(_Family):
    name, ext = "powershell", ".ps1"

    def assign(self, name, expr):
        return f"${name} = {expr}"

    def ref(self, name):
        return f"${name}"

    def join(self, parts):
        return "-join @(" + ", ".join(_q(p) for p in parts) + ")"

    def concat(self, exprs):
        return "(" + " + ".join(exprs) + ")"

    def chars(self, codes):
        return "-join ([char[]](" + ", ".join(map(str, codes)) + "))"

    def prop(self, obj, key, value):
        return [f"${obj} = @{{ {key} = {_q(value)} }}"], f"${obj}.{key}"

    def heredoc(self, name, value):
        return [f"${name} = @'", value, "'@"]

    def print_stmt(self, expr):
        return f"Write-Output {expr}"


class _Bash(_Family):
    name, ext = "bash", ".sh"
    header = ("#!/bin/bash",)
    skip = ("property",)

    def assign(self, name, expr):
        return f"{name}={expr}"

    def ref(self, name):
        return f'"${{{name}}}"'

    def join(self, parts):
        return "\"$(printf '%s' " + " ".join(_q(p) for p in parts) + ')"'

    def concat(self, exprs):
        return "".join(exprs)

    def chars(self, codes):
        return "\"$(printf '" + "".join(f"\\{c:03o}" for c in codes) + "')\""

    def heredoc(self, name, value):
        return [f"{name}=$(cat <<'EOF'", value, "EOF", ")"]

    def print_stmt(self, expr):
        return f"printf '%s\\n' {expr}"


class _Php(_Family):
    name, ext, comment = "php", ".php", "//"
    header = ("<?php",)

    def assign(self, name, expr):
        return f"${name} = {expr};"

    def ref(self, name):
        return f"${name}"

    def join(self, parts):
        return 'implode("", [' + ", ".join(_q(p) for p in parts) + "])"

    def concat(self, exprs):
        return " . ".join(exprs)

    def chars(self, codes):
        return 'implode(array_map("chr", [' + ", ".join(map(str, codes)) + "]))"

    def prop(self, obj, key, value):
        return [f"${obj} = [{_q(key)} => {_q(value)}];"], f"${obj}[{_q(key)}]"

    def heredoc(self, name, value):
        return [f"${name} = <<<'EOF'", value, "EOF;"]

    def print_stmt(self, expr):
        return f'echo {expr} . "\\n";'


class _Ruby(_Family):
    name, ext = "ruby", ".rb"

    def join(self, parts):
        return "[" + ", ".join(_q(p) for p in parts) + "].join"

    def chars(self, codes):
        return "[" + ", ".join(map(str, codes)) + '].pack("U*")'

    def prop(self, obj, key, value):
        return [f"{obj} = {{ {key}: {_q(value)} }}"], f"{obj}[:{key}]"

    def heredoc(self, name, value):
        return [f"{name} = <<~'EOF'.chomp", f"  {value}", "EOF"]

    def print_stmt(self, expr):
        return f"puts {expr}"


class _Perl(_Family):
    name, ext = "perl", ".pl"

    def assign(self, name, expr):
        return f"my ${name} = {expr};"

    def ref(self, name):
        return f"${name}"

    def join(self, parts):
        return 'join("", (' + ", ".join(_q(p) for p in parts) + "))"

    def concat(self, exprs):
        return " . ".join(exprs)

    def chars(self, codes):
        return 'join("", map { chr } (' + ", ".join(map(str, codes)) + "))"

    def prop(self, obj, key, value):
        return [f"my %{obj} = ({key} => {_q(value)});"], f"${obj}{{{key}}}"

    def heredoc(self, name, value):
        return [f"my ${name} = <<'EOF';", value, "EOF", f"chomp(${name});"]

    def print_stmt(self, expr):
        return f'print {expr} . "\\n";'


class _Lua(_Family):
    name, ext, comment = "lua", ".lua", "--"

    def assign(self, name, expr):
        return f"local {name} = {expr}"

    def join(self, parts):
        return "table.concat({" + ", ".join(_q(p) for p in parts) + "})"

    def concat(self, exprs):
        return " .. ".join(exprs)

    def chars(self, codes):
        return "string.char(" + ", ".join(map(str, codes)) + ")"

    def prop(self, obj, key, value):
        return [f"local {obj} = {{ {key} = {_q(value)} }}"], f"{obj}.{key}"

    def heredoc(self, name, value):
        return [f"local {name} = [[", value + "]]"]

    def print_stmt(self, expr):
        return f"print({expr})"


FAMILIES = {f.name: f for f in (_Python(), _JavaScript(), _AppsScript(), _PowerShell(), _Bash(), _Php(),
                                 _Ruby(), _Perl(), _Lua())}
NOT_APPLICABLE = tuple((f.name, c) for f in FAMILIES.values() for c in f.skip)


def check_tag(tag) -> str:
    if not isinstance(tag, str) or not _TAG_RE.match(tag):
        raise LookaheadError(f"tag {tag!r}: the event's tag is a word of letters, digits and _ "
                             "(starting with a letter, at most 64); there is no default tag")
    return tag


def _rng(seed, family: str, container: str) -> random.Random:
    return random.Random(f"b256:{seed}:{family}:{container}")


def _cuts(s: str, rng: random.Random, lo: int = 3, hi: int = 5) -> list[str]:
    """`s` cut into lo..hi non-empty pieces (so `s` itself is never one literal)."""
    k = min(rng.randint(lo, hi), len(s))
    points = sorted(rng.sample(range(1, len(s)), k - 1))
    return [s[a:b] for a, b in zip([0] + points, points + [len(s)])]


def render(family: str, container: str, tag: str, seed=0) -> Rendered:
    """One file of `family` whose tagged copy lives in `container`. Deterministic in (seed, family,
    container, tag)."""
    f = FAMILIES.get(family)
    if f is None:
        raise LookaheadError(f"family {family!r} is not known (known: {', '.join(FAMILIES)})")
    if container not in CONTAINERS:
        raise LookaheadError(f"container {container!r} is not known (known: {', '.join(CONTAINERS)})")
    if container in f.skip:
        raise LookaheadError(f"container {container!r} is not staged for {family} (see NOT_APPLICABLE)")
    check_tag(tag)
    rng = _rng(seed, family, container)
    payload = "".join(rng.choice(_PAYLOAD_ALPHABET) for _ in range(rng.randint(24, 40)))
    tagged = f"{tag}-{payload}"
    sid = "".join(rng.choice("abcdef0123456789") for _ in range(6))
    var, decoy = f"v_{sid}", f"encoded_{sid}"
    c = f.comment
    lines = list(f.header)
    probe: str | None = f.ref(var)
    if container == "comment":
        lines.append(f"{c} {tagged}")
        probe = None
    elif container == "marker-joined":
        lines += [f"{c} {tag}:SPLIT", f.assign(var, f.join(_cuts(tagged, rng)))]
    elif container == "concat":
        lines += [f"{c} {tag}", f.assign(var, f.concat([_q(p) for p in _cuts(tagged, rng)]))]
    elif container == "charcodes":
        lines += [f"{c} {tag}", f.assign(var, f.chars([ord(ch) for ch in tagged]))]
    elif container == "property":
        stmts, probe = f.prop(f"cfg_{sid}", "tagged", tagged)
        lines += [f"{c} {tag}"] + stmts
    elif container == "heredoc":
        lines += [f"{c} {tag}"] + f.heredoc(var, tagged)
    elif container == "no-comment":
        lines.append(f.assign(var, _q(tagged)))
    elif container == "split-constants":
        cut = rng.randint(1, len(tagged) - 1)
        a, b = f"part_a_{sid}", f"part_b_{sid}"
        lines += [f"{c} {tag}", f.assign(a, _q(tagged[:cut])), f.assign(b, _q(tagged[cut:])),
                  f.assign(var, f.concat([f.ref(a), f.ref(b)]))]
    # the payload in a second place, untagged (cut differently from the tagged copy where it is joined)
    second = f.join(_cuts(payload, rng)) if container == "marker-joined" else _q(payload)
    lines.append(f.assign(decoy, second))
    return Rendered(family, container, f.ext, "\n".join(lines) + "\n", tagged, payload, probe, f.ref(decoy), c)


def _ours(sdir: Path) -> bool:
    try:
        raw = (sdir / _matrix.SPECIMEN_FILE).read_text(encoding="utf-8")
    except OSError:
        return False
    return STAGED_NOTE in raw


def write_specimen(sdir: Path, rs: Rendered, question_id: str = DEFAULT_QID) -> Path:
    """Write one rendered file as a raw-encoded matrix specimen. Refuses a folder this module did not
    stage; rewrites one it did."""
    if sdir.exists():
        if not _ours(sdir):
            raise LookaheadError(f"{sdir}: exists and was not staged by the tagged-copy step; not overwriting")
        shutil.rmtree(sdir)
    (sdir / _matrix.FILES_DIR).mkdir(parents=True)
    member = f"member{rs.ext}"
    (sdir / _matrix.FILES_DIR / member).write_text(rs.text, encoding="utf-8")
    q = {"id": question_id, "answer_format": {"kind": "exact_text"},
         "question": f"What is the tagged copy carried by {member}?"}
    (sdir / _matrix.QUESTIONS_FILE).write_text(json.dumps([q], indent=1), encoding="utf-8")
    (sdir / _matrix.KEY_FILE).write_text(json.dumps({question_id: rs.tagged}), encoding="utf-8")
    note = f"{STAGED_NOTE}: {rs.family}, tagged copy in {rs.container}"
    (sdir / _matrix.SPECIMEN_FILE).write_text(
        f'encoding = ["raw"]\nnote = {json.dumps(note)}\n', encoding="utf-8")
    return sdir


def stage(matrix_dir, lane: str, tag: str, *, seed=0, families=None, containers=None,
          question_id: str = DEFAULT_QID) -> list[str]:
    """Stage every (family, container) pair as a specimen under <matrix>/<lane>/, named
    `tagged-<family>-<container>`. The lane must be declared in the matrix. Returns the specimen names;
    the matrix is re-loaded afterwards so a staged specimen that does not load is an error here."""
    check_tag(tag)
    mdir = Path(matrix_dir)
    m = _matrix.load(mdir)
    if lane not in m.lanes:
        raise LookaheadError(f"{mdir}: lane {lane!r} is not declared in {_matrix.MATRIX_FILE} "
                             f"(declared: {', '.join(m.lanes)}); declare it with its reader first")
    if not isinstance(question_id, str) or not question_id:
        raise LookaheadError("question_id must be a non-empty id")
    fams = list(families) if families else list(FAMILIES)
    cons = list(containers) if containers else list(CONTAINERS)
    for x in fams:
        if x not in FAMILIES:
            raise LookaheadError(f"family {x!r} is not known (known: {', '.join(FAMILIES)})")
    for x in cons:
        if x not in CONTAINERS:
            raise LookaheadError(f"container {x!r} is not known (known: {', '.join(CONTAINERS)})")
    names = []
    for fam in fams:
        for con in cons:
            if con in FAMILIES[fam].skip:
                continue
            name = f"{PREFIX}-{fam}-{con}"
            write_specimen(mdir / lane / name, render(fam, con, tag, seed), question_id)
            names.append(name)
    if not names:
        raise LookaheadError("nothing to stage: every requested (family, container) pair is not applicable")
    _matrix.load(mdir)
    return names
