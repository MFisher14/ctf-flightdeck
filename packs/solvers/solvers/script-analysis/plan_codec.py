#!/usr/bin/env python3
"""Language-blind plan recovery for the Script Analysis lane: no parser, no interpreter.

Usage:
  python3 solvers/script-analysis/plan_codec.py <specimen> [...]     print what each file carries

Every specimen of the lane, whatever its language, stores one plan (`v=<n>|steps=...|adapter=...|`
or a JSON descriptor) as encoded material: a long string literal, a numeric array, or a
`HUNTRESS-MATERIAL:` token. This module recovers it from the text alone:

  1. candidates(text)   every piece of the file that could be material, under every
                        representation it reads as (hex, decimal, base64 in either alphabet,
                        `\\xNN` or octal escapes, a number array; literals joined by an
                        operator or by white space alone; a value built over statements from
                        literals: an append chain, a join of variables, a list joined with ''
                        (whole_values); a literal in other quotes: q{..}, %q(..), [[..]], a
                        one-line here-document (other_literals)). sources(text) is the same
                        list with a grade: whether the candidate used a whole literal or a piece.
                        graded_plans also reads the file with its character calls written as
                        what they return (fold_char_calls: chr(118), string.char(..), 118.chr).
                        Rows 56 to 58 (2026-10-07): a literal over several lines read as ONE
                        value (block_literals; a list over several lines joined with nothing,
                        list_rhs), base32, base85, z85, zlib and gzip, octal and 8-bit binary
                        groups and one nested base64/hex level (more_forms, in a pass after every
                        other reading), and a run of character calls whatever its values
                        (char_runs). Row 78 (2026-10-07): the string forms of C# and F# scripts,
                        Swift, Kotlin scripts, Dart, Julia, Elixir, Clojure, Scheme, Racket, Nim,
                        zsh, fish, awk and single-file Java: <> and * joins, their appends and list
                        joins, Lisp (def ..) forms, interpolated strings of variables, triple-quoted
                        strings whose line ends a call takes out, their character and byte-array
                        calls (MORE_CHAR_CALLS, printf, sprintf), \\u{..}, decimal (F#) and \\x..;
                        (Scheme) escapes; and the glue that makes each of their built values a piece.
                        Row 92: a raw (headerless) deflate stream in a reading or a number list
                        (raw_inflate, bounded; emitted after every other reading);
  2. undo(data)         every byte transform whose key a known-plaintext crib fixes
                        (identity, xor, add, rolling xor, repeating xor, bit rotation, each
                        also on the reversed bytes). The cribs are the plan's first bytes
                        for the versions 1 to 9, and the start of a JSON descriptor;
  3. looks_like_plan    the strict plan grammar. It is the ONLY acceptance: a decode that
                        merely starts with a crib is not a plan. Row 101 (2026-10-08): a plan whose
                        fields come in another order (`v=3|language=..|role=..|..|steps=a,b|..`, Day 8)
                        is accepted by grammar_plan: `v=<n>` first, every field `key=value` with a
                        lowercase key, no key twice, `steps=` a list of step names anywhere, at least
                        four fields, printable ASCII, to its very end. undo() finds it by the crib
                        `v=<n>|<key>=` under the transforms whose key the first byte fixes, and
                        string_forms reads hex written in pieces with one separator (`763d.337c`).
                        Day 9 preparation (2026-10-08): the material under ROT13 (its text, or the base64
                        or hex text it is written in: PHP str_rot13, `tr A-Za-z N-ZA-Mn-za-m`, Python's
                        rot13 codec); a literal whose statement ends behind a call that joins nothing to it
                        ('..'.reverse, '..'.unpack1('m'), '..'[::-1]) is whole (AFTER_WHOLE); and
                        fold_char_calls also writes out a format of literals ("{1}{0}" -f 'b','a',
                        "{}{}".format('a','b'), String.Format, sprintf("%s%s", ..)) and a marker taken out
                        of a literal ('ab@@cd'.Replace('@@',''), -replace, str_replace('@@','','..')).

recover(text) returns (plan text, representation, transform) for the first candidate that
passes, or None. It is the prototype's function, unchanged. Callers use decode(text, ext):
the same answer whenever the file holds one plan in a whole literal, the longest when
candidates are cut copies of one plan, that plan without its last field when only a piece
of the material was read, and None when two candidates decode to different plans (reading()
also says why).

Live fixes. A new language may start its plan differently or label its codec in a new way.
That is fixed without editing this file, by a new file beside it that is loaded by name:

    hooks_<ext>.py          (hooks_hta.py for .hta specimens)
        EXTRA_CRIBS = [b"v=10|steps="]                      # more known plaintext
        LABEL_PATTERNS = [r"CODEC\\s*=\\s*'([^']+)'"]          # group 1 = "rep|transform[|key]"

The grammar stays the only acceptance, also for a hook's crib.

optional(name) is the loader for every such by-name file of the lane (hooks_<ext>,
shapes_<ext>, census, lang_<ext>): None when the file is absent, hidden by the rehearsal
knob, or broken (one stderr line), never an exception.
"""
# Round 2 of the Day 9 preparation (2026-10-08, tests/test_script_b.py): the per-literal searches are bounded
# (row 141: _tail, _uses, _line_start, side_by_side once a line; a literal under 24 characters is not graded),
# and a short literal behind the material that reads as its rest grades the plan a piece (TAILS, _tailed).
import base64
import bisect
import errno as _errno
import functools
import importlib.util
import json
import os
import re
import stat as _stat
import sys
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Known plaintext a plan starts with. `v=1` and the JSON forms come first, so nothing that was
# read before the other version digits were added is read differently.
CRIBS = [b'v=1|steps=', b'{"steps":[', b'{"'] + [b'v=%d|steps=' % n for n in range(2, 10)]
PLAN_RE = re.compile(r'^v=\d+\|steps=[a-z_,]+\|adapter=[^|]+\|')
PLAN_START = re.compile(r'v=\d+\|steps=')
B64 = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
B64_URLSAFE = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')
URLSAFE = str.maketrans('-_', '+/')
# "representation|transform[|key]": what an in-file codec label looks like.
LABEL_RE = re.compile(r'[a-z][a-z0-9_.-]*\|[a-z][a-z0-9_.-]*(?:\|[0-9A-Za-z_,]*)?')
LABEL_PATTERNS = [
    r'HUNTRESS-CODEC:\s*([\w.-]+\|[\w.-]+(?:\|[\w,]*)?)',          # a comment, in any comment syntax
    r'(?i)\bCodec_\w+\s*=\s*["\']([^"\'\r\n]+)["\']',               # Codec_x = "rep|transform|key"
    # Row 71: the same constant behind another assignment, `Codec_x := ".."` (Go, AutoHotkey),
    # `Codec_x <- ".."` (R), a type before the operator (`Codec_x: string = ..` in TypeScript,
    # `Const Codec_x As String = ..` in VBA).
    r'(?i)\bCodec_\w+(?:\s*:\s*[A-Za-z_][\w.]*|\s+As\s+\w+)?\s*(?::=|<-|=)\s*["\']([^"\'\r\n]+)["\']',
    # Row 78: (def Codec_x "..") and (define Codec_x "..") (Clojure, Scheme, Racket), set [-l] Codec_x ".."
    # (fish; Tcl's set Codec_x ".." too), Codec_x::String = ".." (Julia).
    LISP_LABEL := r'(?i)\((?:def|define)[ \t]+Codec_[\w-]+[ \t]+"([^"\r\n]+)"',
    SET_LABEL := r'(?i)\bset[ \t]+(?:-[A-Za-z]+[ \t]+)*Codec_\w+[ \t]+["\']([^"\'\r\n]+)["\']',
    TYPED_LABEL := r'(?i)\bCodec_\w+[ \t]*::[ \t]*[A-Za-z_]\w*[ \t]*=[ \t]*"([^"\r\n]+)"',
]
# Row 78: what a text must hold for each of the three patterns above to be tried (a solve reads every file).
LABEL_GUARDS = {LISP_LABEL: '(def', SET_LABEL: 'set', TYPED_LABEL: '::'}
DELIMITER_NAMES = {':': 'colon', '-': 'dash', ',': 'comma', '.': 'dot', '|': 'pipe', ' ': 'space', ';': 'semicolon'}


# ---------------------------------------------------------------- files loaded by name

HOOK_DIRS = [HERE]   # where by-name files are looked for; a test appends its scratch folder
_optional = {}       # file path -> module, or None for a file that did not load (reported once)
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HOOK_PATHS = {}     # (folder, name) -> (Path(folder) / "<name>.py", its text): no filesystem in it
_IGNORED_ERRNOS = (_errno.ENOENT, _errno.ENOTDIR, _errno.EBADF, _errno.ELOOP)   # pathlib's own list
_IGNORED_WINERRORS = (21, 123, 1921)                                             # pathlib's own list


def _hook_path(folder, name: str):
    """(Path(folder) / f"{name}.py", str of it), kept per (folder, name)."""
    try:
        got = _HOOK_PATHS.get((folder, name))
    except TypeError:                  # a folder that is no hashable path: built every time
        p = Path(folder) / f"{name}.py"
        return p, str(p)
    if got is None:
        p = Path(folder) / f"{name}.py"
        got = _HOOK_PATHS[(folder, name)] = (p, str(p))
    return got


def _is_file(text: str) -> bool:
    """Path(text).is_file() exactly (pathlib 3.12): S_ISREG of os.stat; False for the errors pathlib ignores
    (a missing file, a broken symlink) and for a path that cannot be encoded; any other OSError is raised."""
    try:
        return _stat.S_ISREG(os.stat(text).st_mode)
    except OSError as e:
        if getattr(e, "errno", None) in _IGNORED_ERRNOS or getattr(e, "winerror", None) in _IGNORED_WINERRORS:
            return False
        raise
    except ValueError:
        return False


def hidden() -> set:
    """Names in $CTF_HIDE, honoured only with CTF_TESTING=1: a rehearsal knob that makes
    a component look absent. Inert in live play."""
    if ctf_env.get("CTF_TESTING") != "1":
        return set()
    return {n.strip().lower() for n in ctf_env.get("CTF_HIDE", "").split(",") if n.strip()}


def optional(name: str):
    """The module in `<name>.py` beside this file, or None when there is no such file.

    Only this lane's own folder is searched (never the whole import path: an installed
    package that happens to be called `census` is not this lane's census). The file is looked
    for on every call, so a fix written while a process runs is picked up by its next
    specimen. A file that exists but does not import is reported once on stderr and read as
    absent: a broken live fix must cost its own answers, never the solver's."""
    name = str(name)
    if not _NAME_RE.fullmatch(name) or name.lower() in hidden():
        return None
    # The file is still looked for on every call (one stat, as Path.is_file makes it); only the Path object and its
    # text, which depend on nothing but the folder and the name, are kept (perf, Day 27 speed build).
    path = key = None
    for d in HOOK_DIRS:
        p, text = _hook_path(d, name)
        if _is_file(text):
            path, key = p, text
            break
    if path is None:
        return None
    if key in _optional:
        return _optional[key]
    mod = sys.modules.get(name)
    try:
        ours = mod is not None and Path(getattr(mod, "__file__", "") or "").resolve() == path.resolve()
    except OSError:
        ours = False
    if not ours:
        mod = None
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            loaded = importlib.util.module_from_spec(spec)
            fresh = name not in sys.modules      # a file of another folder under this name keeps its place
            if fresh:
                sys.modules[name] = loaded
            try:
                spec.loader.exec_module(loaded)
                mod = loaded
            finally:
                if mod is None and fresh:
                    sys.modules.pop(name, None)
        # Exception and SystemExit only: the runner's time limit arrives as another BaseException
        # (run.SolverTimeout) and must pass through.
        except (Exception, SystemExit) as e:  # noqa: BLE001 - a SyntaxError or sys.exit in a hook file is just "no hook"
            print(f"[plan_codec] {path.name} did not load ({type(e).__name__}: {e}); continuing without it",
                  file=sys.stderr)
    _optional[key] = mod
    return mod


def _is_this(mod, path: Path) -> bool:
    """Whether a loaded module is the file at `path` (resolved); its plain __file__ string is tried first."""
    f = getattr(mod, "__file__", None) if mod is not None else None
    if not f:
        return False
    if f == str(path):
        return True
    try:
        return Path(f).resolve() == path
    except OSError:
        return False


def own(name: str):
    """This lane's own `<name>.py` (the file beside this one), whatever else holds that module name.

    solvers/binary has a generic.py too, and both lanes import theirs by its short name. In a process
    that loaded the Binary solver first (a test module that put solvers/binary on sys.path at import, or a
    runner that serves both lanes), a bare `import generic` hands back the Binary module, and a reader
    that catches its AttributeError answers nothing (SH-05: the Erlang reader returned {} in a full-suite
    run). analyze._own delegates here (one copy of the rule), so both get one shared module: the loaded
    one when it is this file, else this file loaded by path under the name, or under
    `script_analysis_<name>` when another lane's module holds the name (theirs keeps its place).
    Unlike optional() this is for a required sibling: CTF_HIDE does not apply, and a missing or broken
    file raises (ModuleNotFoundError naming the path, or the file's own error), never None. Looked up in
    sys.modules on every call (nothing cached here), so a test that reloads the module is followed."""
    name = str(name)
    if not _NAME_RE.fullmatch(name):
        raise ValueError(f"plan_codec.own: {name!r} is not a module name")
    path = HERE / f"{name}.py"            # HERE is resolved
    for key in (name, f"script_analysis_{name}"):
        mod = sys.modules.get(key)
        if _is_this(mod, path):
            return mod
    if not path.is_file():
        raise ModuleNotFoundError(f"plan_codec.own: the script-analysis lane has no {name}.py ({path})", name=name)
    key = name if name not in sys.modules else f"script_analysis_{name}"
    spec = importlib.util.spec_from_file_location(key, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(key, None)
        raise
    return mod


def text_of(data) -> str:
    """A specimen's bytes as text: UTF-16 with a byte-order mark, else UTF-8, else Latin-1."""
    if isinstance(data, str):
        return data
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def ext_name(ext) -> str:
    """'.HTA' or 'hta' -> 'hta': the form used in file names (hooks_hta.py) and label keys."""
    return re.sub(r"[^a-z0-9]+", "_", str(ext or "").lower().lstrip(".")).strip("_")


def hooks(ext):
    """(extra cribs, label patterns) from hooks_<ext>.py, or two empty lists."""
    name = ext_name(ext)
    mod = optional(f"hooks_{name}") if name else None
    if mod is None:
        return [], []
    cribs = []
    for c in getattr(mod, "EXTRA_CRIBS", None) or []:
        c = c.encode("latin-1", "replace") if isinstance(c, str) else c
        if isinstance(c, (bytes, bytearray)) and len(c) >= 2:
            cribs.append(bytes(c))
    patterns = [p for p in (getattr(mod, "LABEL_PATTERNS", None) or []) if isinstance(p, (str, re.Pattern))]
    return cribs, patterns


# ---------------------------------------------------------------- the grammar

FIELD_RE = re.compile(r'[a-z][a-z0-9_]*=[^|]*')
STEP_LIST = re.compile(r'[a-z][a-z0-9_]*(?:,[a-z][a-z0-9_]*)*')
MIN_FIELDS = 4       # `v=` and three more: a shorter text is no plan by grammar alone


def grammar_plan(t: str):
    """The fields of a plan accepted by grammar alone (row 101), as a table, or None.

    `v=<n>` first, then `key=value` fields with lowercase keys joined by `|` (one `|` may end the plan), no
    key twice, a `steps` field that is a list of step names wherever it stands, MIN_FIELDS fields or
    more, printable ASCII throughout. The whole text must be the plan: unlike PLAN_RE this is no prefix
    match, so two copies written one after the other, or a plan followed by other text, are no plan."""
    # Printable ASCII throughout: `t.isascii() and t.isprintable()` is exactly `all(32 <= ord(c) < 127 for c in t)`
    # (an ASCII character is printable iff it is 0x20..0x7E; perf, Day 27 speed build: a C-speed scan).
    if not isinstance(t, str) or t[:2] != 'v=' or not (t.isascii() and t.isprintable()):
        return None
    parts = t.split('|')
    if parts[-1] == '':
        parts.pop()
    if len(parts) < MIN_FIELDS or not re.fullmatch(r'v=\d+', parts[0]):
        return None
    plan = {}
    for part in parts:
        if not FIELD_RE.fullmatch(part):
            return None
        k, _, v = part.partition('=')
        if k in plan:
            return None
        plan[k] = v
    if not STEP_LIST.fullmatch(plan.get('steps') or ''):
        return None
    return plan


def looks_like_plan(b: bytes):
    try:
        t = b.decode('ascii')
    except UnicodeDecodeError:
        return None
    # t is the ASCII text of b, so `t.isprintable()` is exactly `all(32 <= c < 127 for c in b)` (perf, Day 27).
    if PLAN_RE.match(t) and t.isprintable():
        return t
    if t[:2] == 'v=' and grammar_plan(t) is not None:      # row 101
        return t
    if t[:1] == '{' and t[-1:] == '}':
        try:
            d = json.loads(t)
        except ValueError:
            return None
        if isinstance(d, dict) and d:
            return t
    return None


# ---------------------------------------------------------------- material candidates

STR_RE = re.compile(r'"((?:[^"\\\r\n]|\\.|"")*)"|\'((?:[^\'\\\r\n]|\\.)*)\'')
# A list of numbers; the comma before the closing bracket is Python's `(118, 61, ..., 121,)`.
NUMS_RE = re.compile(r'(?:\[|\(|\{)\s*((?:(?:0x[0-9A-Fa-f]+|&H[0-9A-Fa-f]+|\d+)\s*,\s*){7,}(?:0x[0-9A-Fa-f]+|&H[0-9A-Fa-f]+|\d+))\s*,?\s*(?:\]|\)|\})')
TOKEN_RE = re.compile(r'[A-Za-z0-9+/=%:.,|\-]{40,}')
_LITERAL = r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\')'
# "abc" + "def" (JScript), "abc" & "def" (VBScript), 'abc' + 'def' (PowerShell), "abc" .. "def" (Lua):
# one literal in pieces. An operator may end its line with a continuation mark: `& _` (VBScript, AutoIt),
# `& ¬` (AppleScript).
# Row 78: also "abc" <> "def" (Elixir) and "abc" * "def" (Julia, where * joins strings).
# AutoIt forms fuzz (after Day 12, 2026-10-12): the mark may be followed by a `;` comment up to its line end
# (`"abc" & _ ; note`, AutoIt only: nowhere else does `_ ;` end a line of a join), and the operator may open
# the next line instead of closing this one (`"abc" _` / `& "def"`). Both were read as a join that goes on.
_CONT_MARK = r'[_\u00ac][ \t]*(?:;[^\r\n]*)?\r?\n'
JOINED_RE = re.compile(_LITERAL + r'(?:\s*(?:(?:\.\.|<>|[+&.*])(?:[ \t]*' + _CONT_MARK + r')?'
                       r'|' + _CONT_MARK + r'(?:[ \t]*[+&](?![+&=]))?)\s*' + _LITERAL + r')+')
# "abc" "def": nothing but white space between them (and a string prefix, b"..."). One literal in
# Python, C and Ruby; two arguments in a shell, which is why reading() does not take it on trust.
ADJACENT_RE = re.compile(_LITERAL + r'(?:\s+[bBrRuU]{0,2}' + _LITERAL + r')+')
# 'abc''def': quoted pieces with nothing at all between them. One word in a shell, one literal in
# Python, C and Ruby; a syntax error in JScript, Perl and PHP. (In PowerShell and VBScript a doubled
# quote is an escaped quote, which no encoding alphabet holds, so such a join decodes to nothing.)
TOUCHING_RE = re.compile(_LITERAL + r'(?:' + _LITERAL + r')+')
# (Row 78: also <> and * before or after a literal, and Julia's raw"..": `raw` is a string prefix there.)
GLUE_BEFORE = re.compile(r'(?:[+&*]|<>|\.\.?|["\')\]])[ \t]*$|[A-Za-z0-9_](?<![bBrRuUfF])(?<!\braw)$|[A-Za-z0-9_][bBrRuUfF]{1,2}$')
GLUE_AFTER = re.compile(r'[ \t]*(?:[+&\[*]|<>|\.\.?)|["\'$(]')


# A variable that is appended to: NAME += .., NAME .= .., NAME &= .., NAME = NAME + .. (and & . ..; also
# := and <-), NAME << .. (Ruby, Groovy), append NAME .. (Tcl), set NAME to NAME & .. (AppleScript),
# NAME <- paste0(NAME, ..) (R).
# Row 78: NAME *= .. (Julia), NAME = NAME <> .. (Elixir), NAME = NAME * .., NAME = NAME ".." (awk, literals
# side by side), NAME <- NAME + .. (F#), NAME.add(..) and the other appending methods at a line's start
# (Nim, and a builder's append), NAME = NAME.concat(..), (set! NAME (string-append NAME ..)) and
# (def NAME (str NAME ..)) (Scheme, Clojure), set [-l] NAME "$NAME".. and set -a NAME (fish).
_APPEND_METHOD = r'(?:add|append|Append|push_str|push|concat|Concat|insert|Insert|prepend|extend|plus)'
GROWS_RE = re.compile(r'(?m)^[ \t]*(?:\$?([A-Za-z_]\w*)[ \t]*(?:\+=|\.=|&=|\*=|<>=|<<=?'
                      r'|(?::?=|<-)[ \t]*\$?\1(?:[ \t]*(?:[+&.*]|<>)|[ \t]+(?=["\'$A-Za-z_]))'
                      r'|<-[ \t]*paste0?\([ \t]*\1[ \t]*,'
                      r'|\.' + _APPEND_METHOD + r'[ \t]*\(|(?::?=|<-)[ \t]*\1\.' + _APPEND_METHOD + r'[ \t]*\()'
                      r'|append[ \t]+([A-Za-z_]\w*)[ \t]|set[ \t]+([A-Za-z_]\w*)[ \t]+to[ \t]+\3[ \t]*&'
                      r'|\((?:set!|def|define|setq|setf)[ \t]+([A-Za-z_][\w-]*)[ \t]+\([^\s()]+[ \t]+\4(?![\w-])'
                      r'|set[ \t]+(?:-[A-Za-z]+[ \t]+)*([A-Za-z_]\w*)[ \t]+["\']?\$\{?\5\b|set[ \t]+-[A-Za-z]*a[A-Za-z]*[ \t]+([A-Za-z_]\w*))')
# What may stand between a declared name and its assignment operator: a type (`m: string`, TypeScript and
# Python; `m As String`, VBA).
_TYPED = r'(?:[ \t]*:[ \t]*[A-Za-z_][\w.\[\]<>|]*|[ \t]+As[ \t]+\w+)?'
# The variable a literal is assigned to: NAME = (also += .= &= := <-, and a type before it), set NAME (Tcl),
# set NAME to (AppleScript).
# Row 78: also set -l NAME (fish), (def NAME and (define NAME (Clojure, Scheme), NAME *= (Julia).
ASSIGNED_RE = re.compile(r'(?:(?<![\w$])\$?([A-Za-z_]\w*)' + _TYPED + r'[ \t]*(?:(?:\+|\.|&|:|\*)?=|<-)'
                         r'|\bset[ \t]+(?:-[A-Za-z]+[ \t]+)*([A-Za-z_]\w*)(?:[ \t]+to)?'
                         r'|\((?:def|define)[ \t]+([A-Za-z_][\w-]*))'
                         r'[ \t]*(?:[bBrRuUfF]{0,2}|raw)$')
ASSIGN_WINDOW = 160      # characters before a literal that may hold its NAME = (the longest typed form fits)
# A use of a variable that joins it to something else: an operator before or after it, or another
# variable or word right against it ("$a$b" in Tcl, Perl, PHP and a shell). Row 78: also <> and *.
USE_GLUE_BEFORE = re.compile(r'(?:[+&*]|<>|\.\.?|<<)[ \t]*$|[\w}]$')
USE_GLUE_AFTER = re.compile(r'[ \t]*(?:[+&]|\*(?![*/])|<>|\.\.?(?!\w)|<<)|\$')
# Calls that join their arguments into one string (row 71): R's paste0/paste and str_c, concat and strcat,
# Go's strings.Join and fmt.Sprint, .NET's String.Concat / [string]::Concat. A literal or a variable that is
# one of their arguments beside another is a piece of what they build.
# Row 78: also Julia's string(..), Java's String.join("", ..) and .NET's String.Join("", ..).
# AutoIt forms fuzz (after Day 12, 2026-10-12): also a format call whose arguments are not all literals,
# StringFormat("%s%s", "<piece>", $tail) (AutoIt), sprintf, Sprintf, String.Format, string.format, format!:
# fold_formats writes out a format of literals only, and the one literal of such a call was read as the whole
# value (its plan's last value cut, answered plain: 4 of 16 specimens of the fuzz).
JOIN_CALL = re.compile(r'(?:\bpaste0?|\bstr_c|\b[Cc]oncat|\bstrcat|\bSprint|\bstrings\.Join|::Concat'
                       r'|(?<![\w.])string|\b[Ss]tring\.[Jj]oin'
                       r'|\bStringFormat|\b[Ss]printf|\b[Ss]tring\.[Ff]ormat|(?<![\w.])format!?|(?<![\w.])printf)[ \t]*\($')
# A shell's `$(printf %s%s "<piece>" "$tail")`: the call's name stands BEHIND the bracket (review of 2026-10-12).
SHELL_PRINTF = re.compile(r'[ \t]*(?:builtin[ \t]+|command[ \t]+)?printf\b')
JOIN_SCAN = 400      # characters before a literal searched for the joining call it stands in


def _printf_joins(text, open_at, a, b) -> bool:
    """Whether the shell `$(printf ..)` opened at `open_at` builds its value from more than the literal
    text[a:b]: another argument stands in it besides a format of plain conversions (`%s%s`, `'%s%s\\n'`).
    `printf '<literal>'` and `printf %s '<literal>'` are the literal itself."""
    close = text.find(")", b)
    line_end = text.find("\n", b)
    if close < 0 or (0 <= line_end < close):
        return True                              # the substitution goes on past the line: not one literal
    q0 = a - 1 if a > 0 and text[a - 1] in "\"'" else a
    q1 = b + 1 if b < len(text) and text[b] in "\"'" else b
    rest = SHELL_PRINTF.sub("", text[open_at + 1:q0], count=1) + " " + text[q1:close]
    rest = re.sub(r"""(?:^|\s)(?:--\s+)?["']?(?:%[sbq]|\\n)+["']?(?=\s|$)""", " ", rest, count=1)
    return bool(rest.strip())


def in_join_call(text, a, b) -> bool:
    """Whether text[a:b] is an argument of a JOIN_CALL that has another argument: the innermost
    bracket open before it (a vector `c(..)` or Go's `[]string{..}` taken through) is such a call's,
    and a comma at that depth stands in it before or after text[a:b]. Row 78: also a Lisp form that joins
    (in_lisp_join)."""
    if _has_lisp_join(text) and in_lisp_join(text, a, b):
        return True
    if not _has_join_call(text) or '(' not in text[max(0, a - JOIN_SCAN):a]:
        return False
    depth, i, lo, comma = 0, a - 1, max(0, a - JOIN_SCAN), False
    while i >= lo:
        c = text[i]
        if c in ')]}':
            depth += 1
        elif c in '([{':
            if depth:
                depth -= 1
            else:
                head = text[max(0, i - 40):i + 1]
                if c == '(' and JOIN_CALL.search(head):
                    break
                if c == '(' and SHELL_PRINTF.match(text, i + 1):
                    return _printf_joins(text, i, a, b)
                if c == '(' and re.search(r'(?<![\w.])c\($', head) or c == '{' and head.endswith('[]string{'):
                    comma = comma or _comma_after(text, b)
                    i -= 1
                    continue
                return False
        elif c == ',' and depth == 0:
            comma = True
        i -= 1
    else:
        return False
    return comma or _comma_after(text, b)


@functools.lru_cache(maxsize=16)
def _has_join_call(text) -> bool:
    """Whether the file names a JOIN_CALL at all (most do not: then no literal is looked at)."""
    return re.search(r'paste0?\(|str_c\(|[Cc]oncat\(|strcat\(|Sprint\(|strings\.Join\(|string\(|tring\.[Jj]oin\('
                     r'|StringFormat\(|[Ss]printf\(|tring\.[Ff]ormat\(|format!?\(|\(\s*(?:builtin\s+|command\s+)?printf\b|printf\(',
                     text) is not None


# Row 78: a Lisp form whose head joins its arguments into one string: (str a b) (Clojure), (string-append a b)
# (Scheme, Racket), (string-join (list a b) ""), (clojure.string/join [a b]), (apply str [a b]),
# (apply string-append (list a b)), (string (integer->char 118) ..), (format "%s%s" a b).
LISP_JOIN = re.compile(r'\((?:str|string-append|string-join|clojure\.string/join|apply|string|concat|format)(?=[\s)])')
_LISP_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s()\[\]{}"]+|[()\[\]{}]')
_LISP_NEUTRAL = {"list", "vector", "quote", "str", "string-append", "map", "char", "integer->char"}


@functools.lru_cache(maxsize=16)
def _has_lisp_join(text) -> bool:
    return LISP_JOIN.search(text) is not None


def in_lisp_join(text, a, b) -> bool:
    """Whether text[a:b] stands in a LISP_JOIN form (directly, or through one list or vector of its
    arguments) that has another argument besides it."""
    depth, i, lo, through = 0, a - 1, max(0, a - JOIN_SCAN), 0
    while i >= lo:
        c = text[i]
        if c in ')]}':
            depth += 1
        elif c in '([{':
            if depth:
                depth -= 1
            elif c == '(' and LISP_JOIN.match(text, i):
                return _lisp_args(text, i) > 1
            elif through < 1 and (c in '[{' or text[i - 1:i] == "'" or re.match(r'\((?:list|vector)\s', text[i:i + 8])):
                through += 1
            else:
                return False
        i -= 1
    return False


def _lisp_args(text, i) -> int:
    """The arguments of the form that opens at text[i], its head left out; the items of a list or vector
    among them counted one by one (Lisp has no commas)."""
    depth, n, head, end = 0, 0, True, min(len(text), i + JOIN_SCAN * 4)
    for m in _LISP_TOKEN.finditer(text, i, end):
        tok = m.group(0)
        if tok in '([{':
            depth += 1
        elif tok in ')]}':
            depth -= 1
            if depth <= 0:
                return n
        elif head:
            head = False
        elif depth <= 2 and tok not in _LISP_NEUTRAL and tok != "'":
            n += 1
    return n


def _comma_after(text, b) -> bool:
    """Whether a comma at the depth of text[b] follows it before its bracket closes."""
    depth = 0
    for i in range(b, min(len(text), b + JOIN_SCAN)):
        c = text[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            if not depth:
                return False
            depth -= 1
        elif c == ',' and depth == 0:
            return True
    return False


def _grown(text) -> set:
    return {next(g for g in m.groups() if g) for m in GROWS_RE.finditer(text)}


class _Use:
    """One use of a name: what _joined_use reads of a match (start, end)."""
    __slots__ = ("_s", "_e")

    def __init__(self, s, e):
        self._s, self._e = s, e

    def start(self):
        return self._s

    def end(self):
        return self._e


WORD_INDEX_MIN = 1 << 16     # characters of a text from which _uses reads the words' places once
_WORDS = [None, {}]          # (the text last indexed, {word: [start, ...]})
_LINES = [None, []]          # (the text last indexed, the offsets after each line feed)


def _line_start(text, at) -> int:
    """text.rfind('\\n', 0, at) + 1. For a long text the line starts are read once (row 141: the rfind was
    4.6 s of 5.2 on one line of 20,000 assignments)."""
    if len(text) < WORD_INDEX_MIN:
        return text.rfind('\n', 0, max(at, 0)) + 1
    if _LINES[0] is not text:
        _LINES[0], _LINES[1] = text, [0] + [m.end() for m in re.finditer('\n', text)]
    starts = _LINES[1]
    return starts[bisect.bisect_right(starts, max(at, 0)) - 1]


def _word_char(c: str) -> bool:
    return c == '_' or c.isalnum()


def _uses(text, name):
    """Every match of the pattern `\\$?\\{?\\bNAME\\b\\}?` in the text, found with str.find (row 141: a regex
    scan of the whole text for every assigned literal was 3 s on one line of 2,000 assignments)."""
    if not name or not (_word_char(name[0]) and _word_char(name[-1])):
        yield from re.finditer(r'\$?\{?\b' + re.escape(name) + r'\b\}?', text)
        return
    n, last = len(name), 0
    if len(text) >= WORD_INDEX_MIN and all(map(_word_char, name)):
        # A long text: every word's places, read once (a find per name is O(text) too: 17 s on one line of
        # 20,000 assignments). A name between two word boundaries is a whole run of word characters.
        if _WORDS[0] is not text:
            index = {}
            for m in re.finditer(r'\w+', text):
                index.setdefault(m.group(0), []).append(m.start())
            _WORDS[0], _WORDS[1] = text, index
        places = iter(_WORDS[1].get(name, ()))
    else:
        def found():
            at = text.find(name)
            while at >= 0:
                yield at
                at = text.find(name, at + n)
        places = found()
    for at in places:
        e = at + n
        if (at == 0 or not _word_char(text[at - 1])) and (e == len(text) or not _word_char(text[e])):
            s = at
            if s > last and text[s - 1] == '{':
                s -= 1
            if s > last and text[s - 1] == '$':
                s -= 1
            if text[e:e + 1] == '}':
                e += 1
            yield _Use(s, e)
            last = e


def _joined_use(text, name, a, b) -> bool:
    """Whether the variable `name`, whose value is the literal text[a:b], is used joined to something
    else anywhere in the file: `$m = $a . $b`, `m = a .. tail`, "$a$b". Its value is then a piece."""
    own_line = _line_start(text, a)
    for m in _uses(text, name):
        if own_line <= m.start() < a:            # the name the literal is assigned to
            continue
        line_start = _line_start(text, m.start())
        if _tail(USE_GLUE_BEFORE, text, line_start, m.start()) or USE_GLUE_AFTER.match(text, m.end()) \
                or in_join_call(text, m.start(), m.end()) or side_by_side(text, line_start) \
                or interpolated_use(text, *_bare(text, m, name)) \
                or USE_ADDS.match(text, m.end()) or USE_LISTED.match(text, m.end()):
            return True
        before = LISTED_BEFORE.search(text, max(line_start, m.start() - 200), m.start())
        if before and (',' in before.group(1) or LISTED_NEXT.match(text, m.end())):
            return True
    return False


# Review of 2026-10-08: two more uses that join a variable to something else, which the operators above do
# not show: a method on it that adds text (`full = m.concat("..")`; at a line's start GROWS_RE has it), and a
# list it shares with other items that is then joined (`[m, ".."].join("")`, `"".join([m, ".."])`,
# `-join @($m, '..')`, `implode('', [$m, ".."])`).
USE_ADDS = re.compile(r'[ \t]*\.' + _APPEND_METHOD + r'[ \t]*\(')
USE_LISTED = re.compile(r'[ \t]*,[^\[\]\r\n]{0,200}[\])][ \t]*(?:\.join\b|-join\b)')
LISTED_BEFORE = re.compile(r'(?:\bjoin|\bimplode|-join)[ \t]*(?:\([^()\r\n]{0,60})?[\[(@{]([^\[\]\r\n]*)$')
LISTED_NEXT = re.compile(r'\}?[ \t]*,')


# Row 78: a variable used inside an interpolation ({a} after $" or beside text, \(a), #{a}): joined to the
# rest of its string, whatever that is.
INTERP_BEFORE = re.compile(r'(?:\\\(|#\{|\$\{|\{)[ \t]*$')
INTERP_AFTER = re.compile(r'[ \t]*[)}]')
_INTERP_EDGE = re.compile(r'[\s"\'=(),;]|$')     # what stands beside an interpolation that is a whole value


def _bare(text, m, name) -> tuple:
    """(start, end) of `name` itself inside the match `m` of a use of it ($, braces left out)."""
    s = text.find(name, m.start(), m.end())
    return s, s + len(name)


def interpolated_use(text, s, e) -> bool:
    """Whether the name at text[s:e] (its own braces left out) stands in an interpolation: ${a} anywhere,
    {a}, \\(a) and #{a} inside a string (an odd number of quotes of one kind before it on its line)."""
    after = INTERP_AFTER.match(text, e) if s >= 0 else None
    m = INTERP_BEFORE.search(text, max(0, s - 4), s) if after else None
    if not m:
        return False
    # Only beside something else of its string or word: "${x}" alone, or ${x} alone, is the whole value.
    lone = _INTERP_EDGE
    a, b = m.start(), after.end()
    if text[a - 1:a] == '$' and m.group(0).lstrip().startswith('{'):
        a -= 1                                   # C#'s $"{x}": the $ belongs to the quote
    if (a == 0 or lone.match(text[a - 1])) and lone.match(text, b):
        return False
    if m.group(0).lstrip().startswith('${'):
        return True
    before = text[text.rfind('\n', 0, s) + 1:s]
    return before.count('"') % 2 == 1 or before.count("'") % 2 == 1


# Row 78: an assignment whose right-hand side is two operands or more with only white space between them
# (`m = a b "c"`): one string in awk, a call with arguments elsewhere; either way no operand is the value.
_SIDE_TOKEN = r'(?:\$?\{?[A-Za-z_]\w*\}?|"[^"\r\n]*"|\'[^\'\r\n]*\')'
# Words that may stand before a declared name (`local m`, `let mutable m`, `const string m`).
_DECL_WORDS = (r'(?:(?:local|my|our|var|let|const|def|Local|Global|Dim|Const|readonly|static|final|String'
               r'|string|val|mutable|auto)[ \t]+)*')
SIDE_BY_SIDE = re.compile(r'[ \t]*' + _DECL_WORDS + r'\$?[A-Za-z_]\w*[ \t]*(?::?=|<-)[ \t]*'
                          r'(' + _SIDE_TOKEN + r'(?:[ \t]+' + _SIDE_TOKEN + r')+)[ \t;]*\r?$', re.M)
_KEYWORDS = {"if", "unless", "and", "or", "not", "in", "is", "else", "then", "do", "for", "while", "until",
             "new", "await", "typeof", "instanceof", "return", "yield", "as", "of"}
# A line continuation mark right here, and a next line that opens with a join operator: `_` / `& ".."`.
CONT_JOIN = re.compile(r'[ \t]*[_¬][ \t]*(?:;[^\r\n]*)?\r?\n[ \t]*[+&](?![+&=])')


def side_by_side(text, line_start) -> bool:
    """Whether the line at line_start is a SIDE_BY_SIDE assignment (no keyword among its operands). Asked
    once per line (row 141: the pattern reads the whole line, and every literal of the line asks)."""
    if _SIDE_SEEN[0] is not text:
        _SIDE_SEEN[0], _SIDE_SEEN[1] = text, {}
    seen = _SIDE_SEEN[1]
    if line_start not in seen:
        m = SIDE_BY_SIDE.match(text, line_start)
        if m and m.group(1).endswith("_") and m.group(1)[-2:-1] in " \t" and CONT_JOIN.match(text, m.end(1) - 1):
            # `x = ".." _` whose next line opens with the operator (AutoIt, VB): the `_` is the line's
            # continuation mark and no operand. What is joined on is glued()'s and JOINED_RE's to say.
            rest = m.group(1)[:-1].rstrip(" \t")
            m = m if re.fullmatch(_SIDE_TOKEN + r'(?:[ \t]+' + _SIDE_TOKEN + r')+', rest) else None
        code = re.sub(r'"[^"\r\n]*"|\'[^\'\r\n]*\'', ' ', m.group(1)) if m else ''
        seen[line_start] = bool(m) and not any(t in _KEYWORDS for t in re.findall(r'[A-Za-z_]\w*', code))
    return seen[line_start]


# A literal followed by a call that joins nothing to it, and then by the end of its statement: Ruby's
# '..'.reverse and '..'.unpack1('m'), JavaScript's '..'.split('').reverse().join(''), Python's '..'[::-1] and
# b'..'.decode(), a trim. The call may change the value (plan_codec reads the literal under every
# representation and its reverse anyway); what matters here is that no other text is joined on, so the literal
# is the whole material and not a piece of it. Anything else behind the literal is glue, as before.
AFTER_WHOLE = re.compile(
    r'(?:\.(?:reverse(?:\(\))?|unpack1\(\s*["\'][mMhH]0?\*?["\']\s*\)|unpack\(\s*["\'][mMhH]0?\*?["\']\s*\)(?:\[0\]|\.first)'
    r'|split\(\s*(?:\'\'|"")\s*\)\.reverse\(\)\.join\(\s*(?:\'\'|"")\s*\)|decode\(\s*(?:["\'](?:utf-?8|ascii|latin-?1)["\'])?\s*\)'
    r'|to_s|toString\(\)|trim\(\)|strip\(\)|chomp|freeze)(?![\w(.\[])|\[::-1\])+'
    r'[ \t]*[;)\]}]*[ \t]*(?:(?:\#|//|--)[^\r\n]*)?\r?$', re.M)


# Row 141. GLUE_BEFORE, JOINS_BEFORE and USE_GLUE_BEFORE end at `$` and reach at most TAIL_REACH characters
# before the blanks that stand in front of the place asked about, so a search from the line's start (O(line)
# for every literal: 2,000 short literals on one minified line cost 0.5 s, 100,000 over 40 s) finds nothing
# that a search of that tail does not. tests/test_script_b.py holds the two against each other.
TAIL_REACH = 4


def _tail(pattern, text, line_start, at):
    """pattern.search(text, line_start, at) for a pattern anchored at `$` (see above), in O(1)."""
    e = at
    while e > line_start and text[e - 1] in ' \t':
        e -= 1
    return pattern.search(text, max(line_start, e - TAIL_REACH), at)


_SIDE_SEEN = [None, {}]      # (the text last asked about, {line start: side_by_side}): one line, many literals


def glued(text, a, b, grown=None):
    """Whether the literal text[a:b] (quotes included) is joined to code that is not a literal: an operator
    or another word part right before or after it (chr(87)+'...', "$(printf ..)"'...', '...'[3:]), or the
    value of a variable that is appended to (NAME += ..., NAME = NAME & ...). Such a literal is a piece of a
    longer value: what it decodes to may lack an end (2026-10-06, tests/variants.py)."""
    line_start = _line_start(text, a)
    after = GLUE_AFTER.match(text, b) or CONT_JOIN.match(text, b)     # `".." _` / `& more`: the value goes on
    if after and text[b:b + 1] in '.[':
        whole = AFTER_WHOLE.match(text, b)
        # (review of 2026-10-08) ..unless the statement goes on in the next line with a join:
        # ("A"[::-1]\n + "B"[::-1]) is one value of two pieces.
        after = not whole or NEXT_JOINS.match(text, whole.end())
    if _tail(GLUE_BEFORE, text, line_start, a) or after or in_join_call(text, a, b) \
            or side_by_side(text, line_start):
        return True
    if FORMAT_ARG.search(text, max(line_start, a - ASSIGN_WINDOW), a):
        return True      # an argument of PowerShell's -f: the format's value is fold_formats' literal, not this one
    if text[b:b + 1] and text[b] in _CONTROL:
        return True      # a binary file read as text: a control byte right behind the quote hides what follows
    if grown is None:
        grown = _grown(text)
    # A bounded window: a search from the line start costs O(line) per literal, O(n*L) on a minified line.
    m = ASSIGNED_RE.search(text, max(line_start, a - ASSIGN_WINDOW), a)
    name = m and (m.group(1) or m.group(2) or m.group(3))
    if name and (name in grown or _joined_use(text, name, a, b)):
        return True
    return not name and call_glued(text, a, b, grown, line_start)


# Review of 2026-10-08. A literal that is the argument of a call, `f("..")`, is joined when the CALL is:
# str_rot13("<piece>") . str_rot13("<rest>"), base64_decode("<piece>") + .., a call whose statement goes on
# in the next line with a join operator, or whose variable is appended to (`$m = f(".."); $m .= f("..")`).
# Before, the closing bracket hid all of that and the piece was read as the whole value (its plan's last
# value cut, answered plain). The call is stepped out of at most CALL_DEPTH times: atob(rev("..")).
CALL_OPEN = re.compile(r'(?:(?<![\w$])\$?([A-Za-z_]\w*)' + _TYPED + r'[ \t]*(?:(?:\+|\.|&|:|\*)?=|<-)[ \t]*)?'
                       r'(?<![\w$.:\\])((?:new[ \t]+)?[A-Za-z_\[$][\w.:\]\\]*)\([ \t]*(?:[bBrRuUfF]{0,2})$')
CALL_CLOSE = re.compile(r'[ \t]*(?:,[ \t]*(?:"[^"\r\n]{0,24}"|\'[^\'\r\n]{0,24}\'|[\w.:$-]{1,24})[ \t]*){0,2}\)')
CALL_JOINS = re.compile(r'[ \t]*(?:[+&](?![+&=])|<>|<<|\.\.(?!\.)|\.(?![\w(]))')
JOINS_BEFORE = re.compile(r'(?:[+&]|<>|<<|\.\.?)[ \t]*$')
NEXT_JOINS = re.compile(r'[ \t]*\r?\n[ \t]*(?:\+(?!\+)|&(?!&)|<>|<<|\.\.?(?=[ \t"\'$]))')
STATEMENT_END = re.compile(r'[ \t]*[;)\]}]*[ \t]*(?:(?:\#|//|--)[^\r\n]*)?(?=\r?\n)')
CALL_DEPTH = 3
# In a binary carrier read as text, `"<piece>"\x01\x00+ "<rest>"`: no operator shows behind the quote.
_CONTROL = frozenset(map(chr, set(range(32)) - {9, 10, 13}))
# A literal right behind `-f` (or behind earlier arguments of it): `$m = "{0}" -f '<piece>'` followed by
# `$m += '<rest>'` was read as a whole literal that no variable holds.
FORMAT_ARG = re.compile(r'["\'][ \t]*-f[ \t]*\(?[ \t]*(?:(?:"[^"\r\n]{0,60}"|\'[^\'\r\n]{0,60}\')[ \t]*,[ \t]*)*$')


def call_glued(text, a, b, grown, line_start) -> bool:
    """Whether the literal text[a:b] is the argument of a call that is itself joined to something (see
    above). False when the literal stands in no call, or in one that nothing is joined to."""
    for _ in range(CALL_DEPTH):
        opened = CALL_OPEN.search(text, max(line_start, a - ASSIGN_WINDOW), a)
        closed = CALL_CLOSE.match(text, b) if opened else None
        if not closed:
            return False
        start, b = opened.start(2), closed.end()
        if CALL_JOINS.match(text, b) or _tail(JOINS_BEFORE, text, line_start, start):
            return True
        end = STATEMENT_END.match(text, b)
        if end and NEXT_JOINS.match(text, end.end()):
            return True
        if opened.group(1):
            return opened.group(1) in grown
        a = start
    return False


RUN_GAP = re.compile(r'[\s+&.,_\\]*[bBrRuU]{0,2}')      # what may stand between two literals of one run
# What may stand between a join of literals and one more literal of it: white space, an operator, a
# line continuation, a comment up to its line end.
CONTINUES = re.compile(r'''(?:[\s+&._\\]|(?:\#|//|--|'|(?i:rem)\b)[^\r\n]*(?=[\r\n]))*[bBrRuU]{0,2}''')
# A line end between two bare tokens of one wrapped block (a here-document, a multi-line string, a
# comment block): the indentation and a comment leader may follow it.
# Row 56: also over blank lines (a block of one material with a blank line in it is still one block: its first
# lines alone are a piece of it, never the whole).
WRAP_GAP = re.compile(r'''(?:[ \t]*[\\^]?\r?\n[ \t]*(?:\#+|;+|\*+|//+|::|--|'|(?i:rem)\b)?[ \t]*)+''')
TOKEN_EDGE = re.compile(r'''[\s"'()\[\]{}<>;,]''')      # what may stand on either side of a whole bare token
NEW_FIELD = re.compile(r'\|\w+=')
ESCAPE_RE = re.compile(r'\\(?:x([0-9A-Fa-f]{2})|u00([0-9A-Fa-f]{2})|([0-7]{1,3})|(.))|([^\\])', re.S)
# Lua's \ddd is DECIMAL (\65 is "A"), every other language of the lane reads it as octal.
ESCAPE_DECIMAL_RE = re.compile(r'\\(?:x([0-9A-Fa-f]{2})|u00([0-9A-Fa-f]{2})|([0-9]{1,3})|(.))|([^\\])', re.S)
# Row 78: F#'s trigraph \DDD is decimal too.
DECIMAL_ESCAPES = {"lua", "fsx", "fs"}
# Row 78: R7RS Scheme ends a hex escape with a semicolon, \x76; (Racket's own reader does not).
SEMICOLON_ESCAPES = {"scm", "ss", "sls", "sld"}


@functools.lru_cache(maxsize=4)
def _escape_re(dialect: str):
    """ESCAPE_RE for a dialect ('' octal, 'decimal', 'scheme'): groups hex, \\u00XX, \\u{XX} (Swift, Rust,
    Elixir, Dart; row 78), the number, a simple escape, a plain character."""
    x = r'x([0-9A-Fa-f]{1,2});' if dialect == 'scheme' else r'x([0-9A-Fa-f]{2})'
    num = r'([0-9]{1,3})' if dialect == 'decimal' else r'([0-7]{1,3})'
    return re.compile(r'\\(?:' + x + r'|u00([0-9A-Fa-f]{2})|u\{0*([0-9A-Fa-f]{1,2})\}|' + num + r'|(.))|([^\\])', re.S)


def escape_dialect(ext) -> str:
    """How the language of `ext` reads its numeric escapes: 'decimal', 'scheme' or '' (octal \\ddd)."""
    name = ext_name(ext) if ext is not None else ''
    return 'decimal' if name in DECIMAL_ESCAPES else 'scheme' if name in SEMICOLON_ESCAPES else ''


SIMPLE_ESCAPES = {'\\': 92, '"': 34, "'": 39, 'n': 10, 'r': 13, 't': 9, 'a': 7, 'b': 8, 'f': 12, 'v': 11}

# How much of a literal a candidate used. The grammar has no end mark, so a plan read from a
# piece may be cut in its last value; reading() decides what to keep.
PIECE, ADJACENT, WHOLE = 0, 1, 2
MAX_LISTS = 8        # number lists in one file whose longer runs are still tried


def _ints(s):
    out = []
    for t in re.split(r'\s*,\s*', s.strip()):
        t = t.strip()
        out.append(int(t[2:], 16) if t[:2].lower() in ('0x', '&h') else int(t))
    return out


def _alphabet(s: str):
    """'b64' or 'num' for a long literal written in an encoding's alphabet, else None: two
    neighbours of one alphabet are pieces of one material."""
    if len(s) < 24:
        return None
    if re.fullmatch(r'[A-Za-z0-9+/=_-]+', s):
        return 'b64'
    return 'num' if re.fullmatch(r'[0-9A-Fa-f:,.|; %x\\-]+', s) else None


def unescaped(s: str, decimal=False):
    """The byte values of a literal spelled with numeric escapes (`\\x79\\x70`, `\\171\\160`, `\\u{79}`), or
    None: no such escape in it, an escape this reader does not know, or a character over 255.
    `decimal` reads `\\ddd` as a decimal number (Lua, F#) instead of an octal one; it may also be a dialect
    of escape_dialect ('decimal', 'scheme': `\\x79;`)."""
    dialect = 'decimal' if decimal is True else (decimal or '')
    if not re.search(r'\\(?:x[0-9A-Fa-f]{1,2}|u00[0-9A-Fa-f]{2}|u\{|[0-9])' if dialect == 'decimal' else
                     r'\\(?:x[0-9A-Fa-f]{1,2}|u00[0-9A-Fa-f]{2}|u\{|[0-7])', s):
        return None
    out, at = [], 0
    for m in _escape_re(dialect).finditer(s):
        if m.start() != at:
            return None             # a backslash at the very end
        at = m.end()
        hexa, uni, unib, octal, simple, plain = m.groups()
        if hexa or uni or unib:
            out.append(int(hexa or uni or unib, 16))
        elif octal:
            out.append(int(octal, 10 if dialect == 'decimal' else 8))
        elif simple:
            if simple not in SIMPLE_ESCAPES:
                return None
            out.append(SIMPLE_ESCAPES[simple])
        else:
            out.append(ord(plain))
    return out if at == len(s) and all(x < 256 for x in out) else None


def _plans(data, cribs=None) -> list:
    """The plan texts one candidate decodes to, under every transform a crib fixes."""
    out = []
    for _, raw in undo(data, cribs):
        t = looks_like_plan(raw)
        if t and t not in out:
            out.append(t)
    return out


def _lengthens(short: str, longer: str) -> bool:
    """`longer` is the plan `short` with a longer last value and no further field: that value has
    two readings."""
    return (len(longer) > len(short) and longer.startswith(short) and '=' in short.rsplit('|', 1)[-1]
            and not NEW_FIELD.search(longer, len(short)))


def _literals(text: str) -> list:
    """[(start, end, value, alphabet)] of every string literal of the file, in file order."""
    return [(m.start(), m.end(), s, _alphabet(s)) for m in STR_RE.finditer(text)
            for s in (m.group(1) if m.group(1) is not None else m.group(2),)]


def sources(text: str, cribs=None):
    """Yield (how, list_of_byte_values, grade) for every piece of the file that could be material.

    The grade says how much of a literal the candidate used:

      WHOLE     a string literal by itself, literals joined by an operator, a number list or
                two in a row, a bare token that ends where the text around it ends it;
      ADJACENT  literals with only white space between them, read as one;
      PIECE     one of a run of like literals (two neighbours in one encoding's alphabet), and
                the join of like literals that follow one another with other text between
                them; a join that has one more literal before or after it, behind an operator
                or a comment; three number lists or more in a row, and every number list of a
                file that holds more than MAX_LISTS; a token cut out of a longer literal; a
                bare token that stops at a character of its own word (the `_` of url-safe
                base64); a line of a wrapped block of bare tokens, and the block's join.

    One join is no candidate at all: number lists whose last (or first) list only lengthens the
    last value of the plan the others give (a second list that is no part of the material, as
    the eight numbers of `chr_join` behind a Python specimen's). The shorter join is then a
    PIECE, for that value has two readings. `cribs` are the caller's (graded_plans: with the
    hook's); the built-in ones when None."""
    for how, data, grade, _ in _sources(text, _literals(text), cribs):
        yield how, data, grade


def _sources(text: str, lits: list, cribs=None, ext=None):
    """sources(), each candidate with the string it was read from (None for number lists). `ext`
    says how the language reads `\\ddd` (DECIMAL_ESCAPES)."""
    decimal = escape_dialect(ext)
    seen = set()

    def emit(how, data):
        data = list(data)
        if len(data) >= 24:
            # Perf (Day 27 speed build): bytes() of a list of ints succeeds exactly when every value is in 0..255,
            # so it is the range test, in C. Anything it refuses goes to the test of before, which decides (or
            # raises) as it did: a value out of range is no candidate.
            try:
                k = bytes(data)
            except (TypeError, ValueError):
                if not all(0 <= x < 256 for x in data):
                    return
                k = bytes(data)
            if k not in seen:
                seen.add(k)
                yield how, data

    arrays = [_ints(m.group(1)) for m in NUMS_RE.finditer(text)]
    few = len(arrays) <= MAX_LISTS
    spans = [(i, i + 1) for i in range(len(arrays))] + [(i, i + 2) for i in range(len(arrays) - 1)]
    if few:                                        # longer runs, while the lists are few
        spans += [(i, j) for i in range(len(arrays) - 2) for j in range(i + 3, len(arrays) + 1)]
    decoded = {}

    def joined(i, j):
        return arrays[i] if j == i + 1 else [x for a in arrays[i:j] for x in a]

    def plans_of(i, j):
        if (i, j) not in decoded:
            decoded[i, j] = _plans(joined(i, j), cribs) if all(0 <= x < 256 for a in arrays[i:j] for x in a) else []
        return decoded[i, j]

    left_out, doubtful, array_deflated = set(), set(), []
    for i, j in spans:
        if j - i > 1 and plans_of(i, j):
            for part in ((i, j - 1), (i + 1, j)):
                if any(_lengthens(p, t) for p in plans_of(*part) for t in plans_of(i, j)):
                    left_out.add((i, j))
                    doubtful.add(part)
    for i, j in spans:
        if (i, j) in left_out:
            continue
        # Three lists or more in a row are a piece, for no one says where the run ends; so is
        # every list of a file with more lists than are tried as runs.
        g = WHOLE if few and j - i < 3 and (i, j) not in doubtful else PIECE
        for how, data in emit('int_array' if j == i + 1 else 'int_array_concat', joined(i, j)):
            yield how, data, g, None
            r = raw_inflate(bytes(data)) if max(data) < 256 else None
            if r:       # row 92: .NET DeflateStream bytes as a number list, read after every other reading
                array_deflated.append((how + '+raw_deflate', r, g))
    grade = {}

    def note(s, g):
        if len(s) >= 24 and g > grade.get(s, -1):
            grade[s] = g

    kinds = [k for _, _, _, k in lits]
    grown = _grown(text)
    for i, (a, b, s, _) in enumerate(lits):
        run = kinds[i] and ((i and kinds[i - 1] == kinds[i] and RUN_GAP.fullmatch(text, lits[i - 1][1], a))
                            or (i + 1 < len(lits) and kinds[i + 1] == kinds[i] and RUN_GAP.fullmatch(text, b, lits[i + 1][0])))
        if len(s) < 24:
            continue                             # note() keeps nothing shorter: its grade is never asked (row 141)
        note(s, PIECE if run or glued(text, a, b, grown) else WHOLE)
    starts, ends = [a for a, _, _, _ in lits], [b for _, b, _, _ in lits]
    for pattern, g in ((JOINED_RE, WHOLE), (ADJACENT_RE, ADJACENT), (TOUCHING_RE, WHOLE)):
        for m in pattern.finditer(text):
            # One more literal behind an operator or a comment, before the join or after it
            # (whatever its length): the join is a piece of a longer one.
            after, before = bisect.bisect_left(starts, m.end()), bisect.bisect_right(ends, m.start()) - 1
            more = (after < len(lits) and CONTINUES.fullmatch(text, m.end(), starts[after])) \
                or (before >= 0 and CONTINUES.fullmatch(text, ends[before], m.start())) \
                or glued(text, m.start(), m.end(), grown)
            # (glued: code that is no literal joined before or after it, chr(118) . "..." . "...", or
            # a variable that grows or is joined elsewhere: the join is a piece of the value.)
            note(''.join(a or b for a, b in re.findall(r'"([^"\r\n]*)"|\'([^\'\r\n]*)\'', m.group(0))), PIECE if more else g)
    # Like literals that follow one another with other text between them (a variable per chunk,
    # a list, an operator not read above): their join, as a piece, for no one says where it ends.
    i = 0
    while i < len(lits):
        j = i
        while kinds[i] and j + 1 < len(lits) and kinds[j + 1] == kinds[i]:
            j += 1
        if j > i:
            note(''.join(s for _, _, s, _ in lits[i:j + 1]), PIECE)
        i = j + 1
    for value, g in whole_values(text, ext):
        note(value, g)
    for value, a, b, after in other_literals(text):
        tail = NO_OP_CALL.match(text, after)
        stuck = glued(text, a, b, grown) or (after != b and GLUE_AFTER.match(text, tail.end() if tail else after))
        note(value, PIECE if stuck else WHOLE)
    for value, a, b, after in block_literals(text):  # row 56: a literal written over several lines, as ONE value
        note(value, PIECE if block_piece(text, a, b, after, grown) else WHOLE)

    def labelled(tok, g):
        note(tok, g)
        if ':' in tok:                             # LABEL:material
            note(tok.split(':', 1)[1], g)

    bare = []                                      # the tokens outside every literal
    for m in TOKEN_RE.finditer(text):
        tok, a, b = m.group(0), m.start(), m.end()
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0 and b <= ends[i]:
            # Inside a literal: the literal itself when it is all of it, else a piece of it.
            labelled(tok, grade.get(tok, PIECE) if (a, b) == (starts[i] + 1, ends[i] - 1) else PIECE)
        else:
            bare.append((a, b, tok, _alphabet(tok) or _alphabet(tok.partition(':')[2])))
    block = []
    for k, (a, b, tok, kind) in enumerate(bare):
        # A line of a wrapped block: the token before or after it, across a line end, is of its alphabet.
        above = bool(kind and k and bare[k - 1][3] == kind and WRAP_GAP.fullmatch(text, bare[k - 1][1], a))
        below = bool(kind and k + 1 < len(bare) and bare[k + 1][3] == kind and WRAP_GAP.fullmatch(text, b, bare[k + 1][0]))
        edged = (a == 0 or TOKEN_EDGE.match(text[a - 1])) and (b == len(text) or TOKEN_EDGE.match(text[b]))
        if edged and a and text[a - 1] in '"\'`' and not text[b:].strip() and text[_line_start(text, a):a - 1].strip():
            # Review of round 2 (2026-10-08): the file's last token, opened by a quote behind code and never
            # closed (`m = 'SENG..` and the end of the file): a file cut inside its literal. It was read as a
            # whole value and its cut last field answered plain.
            edged = False
        labelled(tok, WHOLE if edged and not above and not below else PIECE)
        if above:
            block.append(tok)
        else:
            block = [tok]
        if len(block) > 1 and not below:           # the block's join: a piece, for a short last line is no token
            labelled(''.join(block), PIECE)
    order, read = sorted(grade, key=len, reverse=True), {}
    rot13 = ROT13_HINT.search(text) is not None
    for s in order:
        got = read[s] = []

        def kept(how, data, got=got):              # emit, keeping every reading for more_forms
            got.append((how, data))
            yield from emit(how, data)
        for how, data in string_forms(s, kept, decimal):
            yield how, data, grade[s], s
    # Rows 57 and 58, in a pass of their own after every reading above: a candidate they add can never
    # take the place (the representation name, the grade) of bytes an earlier reading already gave.
    for s in order:
        for how, data in more_forms(s, emit, decimal, read[s], rot13):
            yield how, data, grade[s], s
    for data, a, b in char_runs(text):
        for how, got in emit('char_calls', data):
            yield how, got, PIECE if glued(text, a, b, grown) else WHOLE, None
    for how, data, g in array_deflated:
        for how, got in emit(how, data):
            yield how, got, g, None


# ---------------------------------------------------------------- literals in other quotes

# Literals the two quote characters do not delimit, whose body is one line: a Lua long bracket
# [==[..]==], Perl's q{..} qq{..} q(..), Ruby's %q(..) %Q{..} %(..), a Tcl word in braces {..},
# a here-document (PHP <<<'EOT', Perl and Ruby <<'EOT' <<~EOT, a shell <<EOF) whose body is one line.
# Row 71: a backquoted string with no substitution in it (Go's raw string, a JavaScript or TypeScript
# template), a raw string r"(..)" (R, and C++'s R"(..)"), a PowerShell here-string @'..'@ and an
# AutoHotkey continuation section "(..)" whose body is one line. A pattern with a group named `body`
# gives its body by that name.
OTHER_LITERALS = [
    re.compile(r'\[(=*)\[([^\r\n]*?)\]\1\]'),
    re.compile(r'(?<![\w$])qq?\s*(?:\{([^{}\r\n]*)\}|\(([^()\r\n]*)\)|\[([^\[\]\r\n]*)\]|<([^<>\r\n]*)>)'),
    re.compile(r'(?<![\w$])%[qQ]?(?:\{([^{}\r\n]*)\}|\(([^()\r\n]*)\)|\[([^\[\]\r\n]*)\])'),
    re.compile(r'(?<=[ \t])\{([^{}\r\n$\[\]\\"]{24,})\}(?=[ \t]*(?:;|\r?$|\]))', re.M),
    re.compile(r'(?<![\w`\\])`(?P<body>(?:[^`\r\n$\\]|\$(?!\{)){24,})`'),
    re.compile(r'(?<![\w"])[rR]"(?P<dash>-*)[(\[{](?P<body>[^\r\n]{24,}?)[)\]}](?P=dash)"'),
    re.compile(r'@(?P<q>[\'"])[ \t]*\r?\n(?P<body>[^\r\n]{24,})\r?\n(?P=q)@'),
    re.compile(r'"[ \t]*\r?\n[ \t]*\([^\r\n]*\r?\n(?P<body>[^\r\n]{24,})\r?\n[ \t]*\)[ \t]*"'),
]
HEREDOC = re.compile(r'<<<?[~-]?[ \t]*(["\']?)([A-Za-z_]\w*)\1([^\r\n]*)\r?\n([^\r\n]*)\r?\n[ \t]*\2\b')
# Perf (Day 27 speed build): for each pattern of OTHER_LITERALS, in its order, the texts any match must hold (one
# of the tuple): `[`, `q`, `%`, `{`, a backquote, r" or R", `@`, a double quote. HEREDOC needs `<<`.
_OTHER_GUARDS = (('[',), ('q',), ('%',), ('{',), ('`',), ('r"', 'R"'), ('@',), ('"',))
# A call after a literal that only takes white space off its ends: not a join.
NO_OP_CALL = re.compile(r'\.(?:chomp|strip|rstrip|lstrip|trim|freeze)\b(?:\(\))?')


def other_literals(text: str) -> list:
    """[(value, start, end, after)] of the literals of OTHER_LITERALS and HEREDOC: their body, where the
    literal stands, and where the code after it on its first line goes on (for a here-document: right
    after its opener; else its end)."""
    out = []
    for k, pattern in enumerate(OTHER_LITERALS):
        if k < len(_OTHER_GUARDS) and not any(g in text for g in _OTHER_GUARDS[k]):
            continue                    # perf (Day 27): the pattern cannot match a text without these
        for m in pattern.finditer(text):
            body = m.group("body") if "body" in pattern.groupindex else \
                next((g for g in m.groups()[1 if pattern is OTHER_LITERALS[0] else 0:] if g is not None), None)
            if body is not None and len(body.strip()) >= 24:
                out.append((body.strip(), m.start(), m.end(), m.end()))
    for m in (HEREDOC.finditer(text) if '<<' in text else ()):
        body = m.group(4).strip()
        if len(body) >= 24:
            out.append((body, m.start(), m.start(4) + len(m.group(4)), m.start(3)))
    return out


# ---------------------------------------------------------------- literals over several lines (row 56)

# A literal whose body runs over two lines or more: a here-document (PHP <<<'EOT' and <<<EOT, Perl and
# Ruby <<'EOT' <<~EOT <<-EOT, a shell <<EOF), a Lua long bracket [[..]], a backquoted string (Go's raw
# string, a JavaScript or TypeScript template), a PowerShell here-string @'..'@ / @"..."@, an R raw
# string r"(..)" and an AutoHotkey continuation section "(..)". Its value is read as ONE value
# (block_value). A body that a language would expand ($x, ${..}, #{..}, `..` in a here-document whose
# marker is not single-quoted; ${ in a template; $ in @".."@) is not read.
BLOCK_OPEN = re.compile(r'<<<?[~-]?[ \t]*(?P<q>["\']?)(?P<id>[A-Za-z_]\w*)(?P=q)'
                        r'|\[(?P<eq>=*)\[|`|@(?P<ps>[\'"])[ \t]*\r?\n|(?<![\w"])[rR]"(?P<dash>-*)(?P<br>[(\[{])'
                        r'|(?P<tq>"""|\'\'\'(?!\'))'
                        r'|"[ \t]*\r?\n[ \t]*\((?P<opts>[^\r\n]*)\r?\n')
# Row 78: a triple-quoted string over several lines (C#, F#, Swift, Kotlin, Java, Julia, Elixir, Nim, Dart, and
# Python): its body up to the same three quotes. A backslash at a line's end joins the next line to it (Swift,
# Julia, Java); any other backslash, an expansion ($, \(, #{) or an f-prefix makes it no literal.
_CONTINUED_LINE = re.compile(r'\\[ \t]*\r?\n[ \t]*')
BLOCK_SCAN = 200_000     # characters a block may run over, at most
_EXPANDS = re.compile(r'\$|`|#\{')
_CLOSE_OF = {'(': ')', '[': ']', '{': '}'}
# A call after a block that only takes its line ends (or all white space) out: no join. Ruby's
# .delete("\n"), .gsub(/\s+/, ""), .tr("\n", ""); JavaScript's .replace(/\s/g, ''), .replaceAll('\n', '').
# Row 78: also .Replace("\n", "") (C#, F#), .replacingOccurrences(of: "\n", with: "") (Swift) and
# |> String.replace("\n", "") (Elixir).
STRIP_CALL = re.compile(r'\.(?:delete\(\s*(["\'])\\n\1\s*\)'
                        r'|(?:gsub|replace|replaceAll|tr|Replace)\(\s*(?:/\\[sn]\+?/g?|(["\'])\\[sn]\+?\2)\s*,\s*(?:""|\'\')\s*\)'
                        r'|replacingOccurrences\(\s*of:\s*"\\n"\s*,\s*with:\s*""\s*\))'
                        r'|[ \t]*\|>[ \t]*String\.replace\(\s*"\\n"\s*,\s*""\s*\)')


# Day 12 look-ahead (S1): the lines of a decimal list (`127 70 58 ..`; also with `,` `:` `;` `|` `.` `-`, blanks
# beside it or not), each cut after a whole number with its separator left out and continued with a backslash.
# The join with nothing makes one number of the two at such a seam (`.. 122\` and `126 ..` gave `122126`), and a
# reader that passes over the number that is no byte loses two characters of the plan a seam: `tps://..` for
# `https://..`, a wrong plain answer in the rehearsal of the next components.
_LIST_SEP = re.compile(r'\d([ \t]*[:,.|;-][ \t]*|[ \t]+)\d')
_SEAM_DIGITS = 4         # digits read on either side of a seam: a byte has three at most
_KEPT_LINE_END = re.compile(r'\d[ \t]*\r?\n[ \t]*\d')    # a digit, a line end the block keeps, a digit
_NO_OCTAL_DIGIT = re.compile(r'[^\D0-7]')                # an 8, a 9, or a digit that is not ASCII


def _continued(raw: str, taken_out: bool = False):
    """The body `raw` of a triple-quoted string with its continued lines joined (_CONTINUED_LINE), or None.
    `taken_out`: a call after the block takes out the line ends it keeps (STRIP_CALL).

    The join is with nothing, as the language makes it, but for the lines of a decimal list where a line ends
    in a digit and the next one begins with one. Such a seam is one number cut in two or two numbers whose
    separator was left out, and the number the join makes says which only when it is no byte (more than three
    digits, or over 255): then it is two. When every such seam of the block shows two numbers, the lines are
    joined there with the list's separator, as block_value joins the lines of any other block. When only some
    do, the others may be either and no join is proven: None, the block is no literal. When none does, the
    join with nothing stands, as before.

    Review of S1: the join with the separator proves the list only when the continued lines are all of its
    seams. A line end the block keeps (no backslash) between two numbers, which a call then takes out, is a
    seam of the same kind that block_value joins its own way (with nothing when the separator has no blank):
    with every continued line repaired around it, it made one number of two again, `acqui_remote` for
    `acquire_remote`, plain, where the unrepaired block had decoded to nothing. Such a block is no literal
    either. (With no such call the kept line ends stay in the value and the block is read as before.)
    And "no byte" holds for the list's own base: in a block with no 8 and no 9 the numbers may be octal
    (`150 164 164 160`), where `2` and `56` make 256, the byte 174 cut in two. Three digits that are an octal
    byte there prove nothing, as a decimal byte proves nothing."""
    seams = list(_CONTINUED_LINE.finditer(raw))
    if not seams:
        return raw
    plain = _CONTINUED_LINE.sub('', raw)
    octal = not _NO_OCTAL_DIGIT.search(raw)
    two = {}                              # where a digit meets a digit: whether the number they make is no byte
    for s in seams:
        left = re.search(r'\d*$', raw[max(0, s.start() - _SEAM_DIGITS):s.start()]).group(0)
        right = re.match(r'\d*', raw[s.end():s.end() + _SEAM_DIGITS]).group(0)
        if left and right:
            n = left + right
            two[s.start()] = len(n) > 3 or int(n) > 255 and not (octal and int(n, 8) < 256)
    if not any(two.values()):
        return plain
    lines = [x for x in (y.strip() for y in _CONTINUED_LINE.sub('\n', raw).splitlines()) if x]
    sep = _LIST_SEP.search('\n'.join(lines))
    d = sep.group(1) if sep else ''       # (a number a line shows no separator: nothing to join with)
    mark = re.escape(d.strip())           # a line may begin or end with the mark of the separator it kept
    listed = re.compile(r'(?:' + mark + r'[ \t]*)?\d{1,3}(?:[ \t]*' + mark + r'[ \t]*\d{1,3})*(?:[ \t]*' + mark + r')?'
                        if mark else r'\d{1,3}(?:[ \t]+\d{1,3})*')
    if not all(listed.fullmatch(x) and all(int(n) < 256 for n in re.findall(r'\d+', x)) for x in lines):
        return plain                      # no decimal list: the join as it was
    if not d or not all(two.values()):
        return None
    if taken_out and _KEPT_LINE_END.search(plain):
        return None                       # a kept line end between two numbers, taken out later: not this join's
    out, at = [], 0
    for s in seams:
        out.append(raw[at:s.start()])
        if s.start() in two:
            out.append(d if mark else ' ')
        at = s.end()
    return ''.join(out) + raw[at:]


def block_value(body: str):
    """The value of a block's body: its lines, each without the white space at its ends, joined with
    nothing when no line holds white space of its own (a wrapped token: base64, hex, a number list cut
    after its delimiter), else with one space. Blank lines at either end are dropped. None when the
    value is under 24 characters."""
    lines = [x.strip() for x in body.splitlines()]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    if any(not x for x in lines):
        return None                    # a blank line inside: more than one value
    value = ('' if not any(re.search(r'\s', x) for x in lines) else ' ').join(lines)
    return value if len(value) >= 24 else None


def _block_at(text: str, m):
    """(body, end, after) of the block whose opener BLOCK_OPEN matched at `m`, or None when it has no
    end: `end` is where the block ends, `after` where code may go on after its opener on the opener's
    line (a here-document's) or after the block (all others). `body` is None for a block whose body
    the language would expand (_EXPANDS), and for a triple-quoted one whose continued lines have no proven
    join (_continued): it is no literal, but it still ends where it ends."""
    stop = min(len(text), m.end() + BLOCK_SCAN)
    if m.group('id'):
        line_end = text.find('\n', m.end(), stop)
        if line_end < 0:
            return None
        c = re.compile(r'(?m)^[ \t]*' + re.escape(m.group('id')) + r'(?!\w)').search(text, line_end + 1, stop)
        if not c:
            return None
        body = text[line_end + 1:c.start()]
        return (None if m.group('q') != "'" and _EXPANDS.search(body) else body), c.end(), m.end()
    tok = m.group(0)
    if tok.startswith('['):
        closer = ']' + m.group('eq') + ']'
        end = text.find(closer, m.end(), stop)
        if end < 0:
            return None
        body = text[m.end():end]          # a bracket inside: a nested list ([[1, 2], [3]]), no long string
        return (None if '[' in body or ']' in body else body), end + len(closer), end + len(closer)
    if m.group('tq'):
        end = text.find(tok, m.end(), stop)
        if end < 0:
            return None
        body = _continued(text[m.end():end], bool(STRIP_CALL.match(text, end + 3)))
        if body is None:                  # line ends that may each be one number or two: no literal
            return None, end + 3, end + 3
        expands = '\\' in body or _EXPANDS.search(body) or text[m.start() - 1:m.start()] in ('f', 'F')
        # Its value keeps the line ends it still has: lines of one material are ONE value only when a call
        # after it takes them out (STRIP_CALL); else they stay what they were before row 78, lines of a block.
        kept = sum(1 for x in body.splitlines() if x.strip()) > 1 and not STRIP_CALL.match(text, end + 3)
        return (None if expands or kept else body), end + 3, end + 3
    if tok == '`':
        end = text.find('`', m.end(), stop)
        if end < 0:
            return None
        body = text[m.end():end]
        return (None if '${' in body or '\\' in body else body), end + 1, end + 1
    if m.group('ps'):
        c = re.compile(r'\r?\n' + m.group('ps') + '@').search(text, m.end() - 1, stop)
        if not c:
            return None
        body = text[m.end():c.start()]
        return (None if m.group('ps') == '"' and _EXPANDS.search(body) else body), c.end(), c.end()
    if m.group('br'):
        closer = _CLOSE_OF[m.group('br')] + m.group('dash') + '"'
        end = text.find(closer, m.end(), stop)
        return None if end < 0 else (text[m.end():end], end + len(closer), end + len(closer))
    c = re.compile(r'\r?\n[ \t]*\)[ \t]*"').search(text, m.end() - 1, stop)   # AutoHotkey's continuation section
    return None if not c else (text[m.end():c.start()], c.end(), c.end())


@functools.lru_cache(maxsize=16)
def block_literals(text: str) -> tuple:
    """((value, start, end, after), ...) of the literals of BLOCK_OPEN whose body runs over two lines or
    more (a one-line body is other_literals'), in file order. Backquotes pair in order: a backquote
    that closes one string never opens the next."""
    if '\n' not in text:
        return ()
    out, quoted = [], 0
    for m in BLOCK_OPEN.finditer(text):
        if (m.group(0) == '`' or m.group('tq')) and m.start() < quoted:
            continue
        got = _block_at(text, m)
        if got is None:
            continue
        body, end, after = got
        if m.group(0) == '`' or m.group('tq'):
            quoted = end
        if body is None or '\n' not in (text[m.end():end] if m.group('tq') else body).strip('\r\n'):
            continue
        value = block_value(body)
        if value is not None:
            out.append((value, m.start(), end, after))
    return tuple(out)


def block_stuck(text: str, a: int, b: int, after: int, grown=None) -> bool:
    """Whether the block text[a:b] is joined to other code (glued), or its opener's line goes on with a
    join after it (`<<<EOT . $x`), a call that only strips white space aside."""
    def past_calls(at):
        tail = NO_OP_CALL.match(text, at) or STRIP_CALL.match(text, at)
        return tail.end() if tail else at
    if glued(text, a, past_calls(b), grown):
        return True
    return after != b and bool(GLUE_AFTER.match(text, past_calls(after)))


# Review of row 56 (2026-10-07). Main read a multi-line material as a wrapped bare-token block, which is
# always a PIECE; a block is now ONE value and may be WHOLE, so it is WHOLE only when nothing in the file can
# make it part of a longer value. Each test below makes it a PIECE (its plan then comes without its last
# field, with the note): a wrong plain last value costs the whole batch, a dropped one costs one answer.
#   - block_stuck: an operator or a join on its own lines;
#   - _beside_comma: it, or a use of its variable, is one item of a list or of a call's arguments
#     ([`A`, `B`].join(''), table.concat({[[A]], [[B]]}), sprintf('%s%s', $a, $tail), -join @($a, $b),
#     '{0}{1}' -f $a, $tail);
#   - a use of its variable that joins (_joined_use, an append, a.concat(..), "{$a}..", `${a}..`);
#   - a shell here-document written to a file that the file appends to (>> or tee -a);
#   - (_graded) another literal or block of its alphabet, at least half its length, that is no plan by itself.
JOINING_METHOD = re.compile(r'[ \t]*\.[ \t]*(?:concat|Concat|insert|Insert|append|Append|prepend|push|format|Format'
                            r'|join|Join|ljust|rjust|padStart|padEnd|PadLeft|PadRight)\b')
_BLOCK_NAME = re.compile(r'(?:(?<![\w$])[$@]?([A-Za-z_]\w*)' + _TYPED + r'[ \t]*(?::=|=|<-)'
                         r'|\bset[ \t]+([A-Za-z_]\w*)(?:[ \t]+to)?)[ \t]*(?:\$\([ \t]*cat[ \t]+)?$')
_APPENDS_TO_FILE = re.compile(r'>>|\btee[ \t]+-a\b|Add-Content|\bappend\b|[\'"]a\+?[\'"]')


def _beside_comma(text: str, a: int, b: int) -> bool:
    """Whether text[a:b] is one item among others: a comma right before or after it, or inside the
    innermost bracket that holds it (a call's arguments, a list, a table constructor)."""
    line_start = text.rfind('\n', 0, a) + 1
    if re.search(r',[ \t]*$', text[max(line_start, a - 200):a]) or re.match(r'[ \t]*,', text[b:b + 200]):
        return True
    depth, i, lo = 0, a - 1, max(0, a - JOIN_SCAN)
    while i >= lo:
        c = text[i]
        if c in ')]}':
            depth += 1
        elif c in '([{':
            if depth:
                depth -= 1
            else:
                if c == '{':                       # a code block's brace is no list: only a constructor's
                    before = text[max(0, i - 40):i].rstrip()
                    if not (before.endswith(('=', '(', ',', '[', '{', ':')) or before.endswith('[]string')):
                        return False
                return ',' in _depth0(text, i + 1, a) or _comma_after(text, b)
        i -= 1
    return False


def _depth0(text: str, a: int, b: int) -> str:
    """The characters of text[a:b] that stand outside every bracket opened within it."""
    out, depth = [], 0
    for c in text[a:b]:
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth = max(0, depth - 1)
        elif not depth:
            out.append(c)
    return ''.join(out)


def block_piece(text: str, a: int, b: int, after: int, grown=None) -> bool:
    """Whether the block text[a:b] may be part of a longer value (the tests above): then a PIECE."""
    sub = _LINE_ENDS_OUT.search(text, max(0, a - 40), a)
    if sub:                                        # row 78: NAME=$(tr -d '\n' <<'EOF' ..): the call is no join
        a = sub.start()
    if block_stuck(text, a, b, after, grown) or _beside_comma(text, a, b):
        return True
    line_start = text.rfind('\n', 0, a) + 1
    head = text[line_start:a]
    if text.startswith('<<', a) and '>' in head.replace('<<', '') and _APPENDS_TO_FILE.search(text):
        return True                                # a here-document written to a file the file appends to
    m = _BLOCK_NAME.search(head)
    name = m and (m.group(1) or m.group(2))
    if not name:
        return False
    if grown is None:
        grown = _grown(text)
    if name in grown:
        return True
    for u in re.finditer(r'(?<![\w$@])[$@]?\{?' + re.escape(name) + r'\b\}?', text):
        if line_start <= u.start() < b:            # the assignment and the block itself
            continue
        ls = text.rfind('\n', 0, u.start()) + 1
        if USE_GLUE_BEFORE.search(text, ls, u.start()) or USE_GLUE_AFTER.match(text, u.end()) \
                or in_join_call(text, u.start(), u.end()) or JOINING_METHOD.match(text, u.end()) \
                or _beside_comma(text, u.start(), u.end()) or text[u.start() - 1:u.start()] == '{' \
                or text[u.start():u.start() + 1] == '{' or text[u.end():u.end() + 1] == '{':
            return True
    return False


_BLANKS = re.compile(r'[ \t]*(?:\$\([ \t]*(?:cat|tr[ \t]+-d[ \t]+([\'"])(?:\\r)?\\n\1)[ \t]+(?=<<))?')  # NAME=$(cat <<'EOF' ..)
# Row 78: a shell's $(tr -d '\n' <<'EOF' ..), which only takes the line ends out of its here-document.
_LINE_ENDS_OUT = re.compile(r'\$\([ \t]*tr[ \t]+-d[ \t]+([\'"])(?:\\r)?\\n\1[ \t]+$')


def block_at(text: str, pos: int):
    """(value, piece) of the block literal that starts at `pos` (white space before it skipped), its
    body on one line or more, or None: label_plan's reading of `Material_x = <<<'EOT' ...`. `piece`
    when it is joined to other code (block_stuck).

    A triple-quoted block whose continued lines have no proven join (_continued) is the empty value, a
    piece: on None the caller reads the statement's own text, where every line end stands between two
    numbers, and that is one of the two joins the block does not prove."""
    m = BLOCK_OPEN.match(text, _BLANKS.match(text, pos).end())
    got = _block_at(text, m) if m else None
    if got is None or got[0] is None:
        if got is not None and m.group('tq') \
                and _continued(text[m.end():got[1] - 3], bool(STRIP_CALL.match(text, got[1]))) is None:
            return '', True
        return None
    body, end, after = got
    value = block_value(body)
    return None if value is None else (value, block_piece(text, m.start(), end, after))


# ---------------------------------------------------------------- a value built from literals

# One statement per line: an assignment, or an append to a variable. The value side is read by _value.
# (Row 78: also `string`, `val`, `mutable` and `auto` before the name: C#, Kotlin, F#.)
_DECL = _DECL_WORDS
# (Row 71: also NAME := .. (Go, AutoHotkey), NAME <- .. (R), and a type before the operator, _TYPED.)
# (Row 78: also set -l NAME .. (fish).)
ASSIGN_LINE = re.compile(r'(?m)^([ \t]*)' + _DECL + r'(?:set[ \t]+(?:-[A-Za-z]+[ \t]+)*([A-Za-z_]\w*)(?:[ \t]+to)?[ \t]+'
                         r'|\$?([A-Za-z_]\w*)' + _TYPED + r'[ \t]*(?::=|<-|=(?![=~]))[ \t]*)(.+?)[ \t;]*\r?$')
# Row 78: (def NAME ..) and (define NAME ..) (Clojure, Scheme, Racket): the rest of the line, the form's own
# closing bracket taken off by lisp_rhs.
LISP_ASSIGN = re.compile(r'(?m)^([ \t]*)\((?:def|define)[ \t]+([A-Za-z_][\w-]*)[ \t]+(.+?)[ \t]*\r?$')
# Row 78: appends whose added value is the one literal of group 3: NAME *= .. (Julia), NAME = NAME <> ..
# (Elixir), NAME = NAME * .. (Julia), NAME.add(..) and the like (Nim; a buffer's append), NAME = NAME ".."
# with white space before the = (awk: literals side by side; a shell has none there), set [-l] NAME
# "$NAME".. (fish), (set! NAME (string-append NAME ..)) and (def NAME (str NAME ..)) (Scheme, Clojure).
_LIT = r'((?:"(?:[^"\\\r\n$`]|\\.)*"|\'[^\'\r\n]*\'))'
EXTRA_GUARDS = (('*=', '<>', '*'), ('.add(', '.append(', '.Append(', '.push_str('), (), ('set ',), ('(set!', '(def'))
# Review of row 78: the right-hand side is taken whatever it is (as in APPEND_LINE), so that an append of
# anything but one literal (m.add(tail), m *= tail(), m.append(chr(65))) is recorded too and disqualifies the
# chain in whole_values (its _ONE_LITERAL check), instead of leaving the literal appends graded WHOLE.
_ANY = r'(.+?)'
EXTRA_APPENDS = [
    re.compile(r'(?m)^([ \t]*)([A-Za-z_]\w*)[ \t]*(?:\*=|=[ \t]*\2[ \t]*(?:<>|\*))[ \t]*' + _ANY + r'[ \t;]*\r?$'),
    re.compile(r'(?m)^([ \t]*)([A-Za-z_]\w*)\.(?:add|append|Append|push_str)\([ \t]*' + _ANY + r'[ \t]*\)[ \t;]*\r?$'),
    re.compile(r'(?m)^([ \t]*)([A-Za-z_]\w*)[ \t]+=[ \t]*\2[ \t]+' + _ANY + r'[ \t;]*\r?$'),
    re.compile(r'(?m)^([ \t]*)set[ \t]+(?:-[A-Za-z]+[ \t]+)*([A-Za-z_]\w*)[ \t]+(?:"\$\2"|\$\2)' + _ANY + r'[ \t;]*\r?$'),
    re.compile(r'(?m)^([ \t]*)\((?:set!|def|define)[ \t]+([A-Za-z_][\w-]*)[ \t]+\((?:string-append|str)[ \t]+\2[ \t]+'
               + _ANY + r'[ \t]*\)\)[ \t]*\r?$'),
]
APPEND_LINE = re.compile(r'(?m)^([ \t]*)(?:\$?([A-Za-z_]\w*)[ \t]*(?:\.=|\+=|&=|<<=?|\.\.=)[ \t]*'
                         r'|\$?([A-Za-z_]\w*)[ \t]*(?::?=|<-)[ \t]*\$?\3[ \t]*(?:\.\.|[.+&])[ \t]*'
                         r'|append[ \t]+([A-Za-z_]\w*)[ \t]+|set[ \t]+([A-Za-z_]\w*)[ \t]+to[ \t]+\5[ \t]*&[ \t]*)'
                         r'(.+?)[ \t;]*\r?$')
# NAME <- paste0(NAME, ..) (R): an append whose added value is the call's other arguments.
APPEND_CALL = re.compile(r'(?m)^([ \t]*)([A-Za-z_][\w.]*)[ \t]*<-[ \t]*paste0\([ \t]*\2[ \t]*,[ \t]*(.+?)\)[ \t;]*\r?$')
# One literal: a double-quoted one without an expansion in it ($ or `), or a single-quoted one.
_ONE_LITERAL = re.compile(r'[bBrRuU]{0,2}(?:"((?:[^"\\\r\n$`]|\\.)*)"|\'([^\'\r\n]*)\')')
_REF = re.compile(r'\$?\{?([A-Za-z_]\w*)\}?')
_OP = re.compile(r'[ \t]*(?:\.\.|<>|[.+&*])[ \t]*')
_SIDE_OP = re.compile(r'[ \t]+')     # awk: operands side by side (_value with `side`)
# A list of literals joined with nothing between them: implode('', [..]) (PHP), join('', ..) (Perl),
# [..].join / .join('') (Ruby, Groovy, JScript), table.concat({..}) (Lua), {..} as text (AppleScript),
# ''.join([..]) (Python), [join [list ..] ""] (Tcl), -join @(..) (PowerShell).
_ITEM = r'(?:"[^"\r\n$`]*"|' + r"'[^'\r\n]*')"
_ITEMS = r'((?:[ \t]*' + _ITEM + r'[ \t]*,)*[ \t]*' + _ITEM + r'[ \t]*,?[ \t]*)'
_TCL_ITEMS = r'((?:[ \t]*"[^"\r\n$\[\\]*")+[ \t]*)'
_EMPTY = r'(?:' + "''" + r'|"")'
LIST_JOINS = [
    re.compile(r'implode\(\s*' + _EMPTY + r'\s*,\s*(?:\[|array\()' + _ITEMS + r'(?:\]|\))\s*\)'),
    re.compile(r'join\(\s*' + _EMPTY + r'\s*,' + _ITEMS + r'\)'),
    re.compile(r'\[' + _ITEMS + r'\]\.join(?:\(\s*(?:' + _EMPTY + r')?\s*\))?'),
    re.compile(r'table\.concat\(\s*\{' + _ITEMS + r'\}\s*\)'),
    re.compile(r'\(\{' + _ITEMS + r'\}\s+as\s+(?:text|string)\)|\{' + _ITEMS + r'\}\s+as\s+(?:text|string)'),
    re.compile(_EMPTY + r'\.join\(\s*[\[(]' + _ITEMS + r'[\])]\s*\)'),
    re.compile(r'\[join\s+\[list' + _TCL_ITEMS + r'\]\s*(?:""|\{\})\s*\]'),
    re.compile(r'-join\s*@?\(' + _ITEMS + r'\)'),
    # Row 71: R's paste0(..) and paste(c(..), collapse = ""), Go's strings.Join([]string{..}, ""),
    # PowerShell's -join in brackets.
    re.compile(r'paste0\(' + _ITEMS + r'\)'),
    re.compile(r'paste\(\s*c\(' + _ITEMS + r'\)\s*,\s*collapse\s*=\s*' + _EMPTY + r'\s*\)'),
    re.compile(r'strings\.Join\(\s*\[\]string\{' + _ITEMS + r'\}\s*,\s*' + _EMPTY + r'\s*\)'),
    re.compile(r'\(\s*-join\s*@?\(' + _ITEMS + r'\)\s*\)'),
    # Row 56: VBA's Join(Array(..), ""), PowerShell's @(..) -join '' and an @(..) whose items stand one a
    # line with no comma (what a list over several lines reads as, its lines joined: list_rhs).
    re.compile(r'Join\(\s*Array\(' + _ITEMS + r'\)\s*,\s*' + _EMPTY + r'\s*\)'),
    re.compile(r'\(?\s*@\(' + _ITEMS + r'\)\s*-join\s*' + _EMPTY + r'\s*\)?'),
    re.compile(r'\(?\s*-join\s*@\(((?:[ \t]*' + _ITEM + r'[ \t]*,?)+)\)\s*\)?'),
    # Row 78: string.Concat(new[] { .. }) and String.Join("", ..) (C#), String.join("", ..) and
    # String.join("", List.of(..)) (Java), String.concat "" [ ..; .. ] (F#), [..].joined() (Swift),
    # listOf(..).joinToString("") (Kotlin), join([..]) and Enum.join([..]) (Julia, Nim, Elixir), and the
    # Lisp forms: (str ..), (string-append ..), (apply str [..]), (apply string-append (list ..)),
    # (clojure.string/join [..]), (string-join (list ..) ""); fish's (string join '' ..).
    re.compile(r'[Ss]tring\.Concat\(\s*new(?:[ \t]+[Ss]tring)?\s*\[\s*\]\s*\{' + _ITEMS + r'\}\s*\)'),
    re.compile(r'[Ss]tring\.[Jj]oin\(\s*' + _EMPTY + r'\s*,(?:\s*new(?:[ \t]+[Ss]tring)?\s*\[\s*\]\s*\{' + _ITEMS
               + r'\}|\s*List\.of\(' + _ITEMS + r'\)|' + _ITEMS + r')\s*\)'),
    re.compile(r'String\.concat\s+' + _EMPTY + r'\s+\[((?:[ \t]*' + _ITEM + r'[ \t]*;)*[ \t]*' + _ITEM + r'[ \t]*;?[ \t]*)\]'),
    re.compile(r'\[' + _ITEMS + r'\]\.joined\(\s*(?:separator:\s*' + _EMPTY + r')?\s*\)'),
    re.compile(r'(?:listOf|arrayOf)\(' + _ITEMS + r'\)\.joinToString\(\s*(?:' + _EMPTY + r')?\s*\)'),
    re.compile(r'(?:Enum\.)?join\(\s*\[' + _ITEMS + r'\]\s*(?:,\s*' + _EMPTY + r'\s*)?\)'),
    re.compile(r'\((?:str|string-append)((?:[ \t]+' + _ITEM + r')+)[ \t]*\)'),
    re.compile(r'\(apply[ \t]+(?:str|string-append)[ \t]+(?:\[((?:[ \t]*' + _ITEM + r')+)[ \t]*\]'
               r'|\(list((?:[ \t]+' + _ITEM + r')+)[ \t]*\)|\'\(((?:[ \t]*' + _ITEM + r')+)[ \t]*\))[ \t]*\)'),
    re.compile(r'\(clojure\.string/join[ \t]+\[((?:[ \t]*' + _ITEM + r')+)[ \t]*\][ \t]*\)'),
    re.compile(r'\(string-join[ \t]+\(list((?:[ \t]+' + _ITEM + r')+)[ \t]*\)[ \t]+""[ \t]*\)'),
    re.compile(r'\(string[ \t]+join[ \t]+' + _EMPTY + r'((?:[ \t]+' + _ITEM + r')+)[ \t]*\)'),
]
LIST_LINES = 400         # lines a list over several lines may run over
# How a list joined with nothing begins (one of LIST_JOINS' calls, or a bare list whose join follows it).
_LIST_HEAD = re.compile(r'implode|join|Join|concat|Concat|paste|@\(|^[ \t]*\[[ \t]*$|\((?:str|string-append|apply)\b'
                        r'|listOf\(|arrayOf\(')
# A call that joins its arguments, each a literal or a variable (R's paste0 of variables).
# (Row 78: also Julia's string(..).)
ARG_JOIN = re.compile(r'(?:paste0|str_c|(?<![\w.])string)\(\s*(.+?)\s*\)')
# Row 78: (str a b ..) and (string-append a b ..) of literals and variables (Clojure, Scheme).
LISP_ARGS = re.compile(r'\((?:str|string-append)((?:[ \t]+(?:"(?:[^"\\\r\n$`]|\\.)*"|[A-Za-z_][\w-]*))+)[ \t]*\)')
_LISP_ARG = re.compile(r'"((?:[^"\\\r\n$`]|\\.)*)"|([A-Za-z_][\w-]*)')


def _items(text: str) -> str:
    return ''.join(a or b for a, b in re.findall(r'"([^"\r\n]*)"|\'([^\'\r\n]*)\'', text))


def _depth(s: str) -> int:
    """Brackets opened and not closed in `s`, its literals left out."""
    code = re.sub(r'"[^"\r\n]*"|\'[^\'\r\n]*\'', '', s)
    return sum(code.count(c) for c in '([{') - sum(code.count(c) for c in ')]}')


def one_line(lines) -> str:
    """Lines of one statement as one line: each without the white space at its ends and a VB `_` at its
    end, joined with one space; no space after an opening bracket, no `;` at the end."""
    joined = ' '.join(x for x in (re.sub(r'[ \t]+_$', '', y.strip()) for y in lines) if x)
    return re.sub(r'([(\[{]) ', r'\1', re.sub(r'[ \t;]+$', '', joined))


def list_value(rhs: str):
    """The value of a right-hand side (over one line or several) that is a LIST_JOINS list joined with
    nothing, or None: label_plan's test of such a side (row 56)."""
    joined = one_line(rhs.splitlines())
    for pattern in LIST_JOINS:
        m = pattern.fullmatch(joined)
        if m:
            return _items(next(g for g in m.groups() if g is not None))
    return None


def list_rhs(text: str, start: int, rhs: str):
    """Row 56: a right-hand side that opens a bracket and closes it on a later line (a list over several
    lines), as one line (one_line). The joined side only when it is a LIST_JOINS list joined with
    nothing; else `rhs`."""
    if not _LIST_HEAD.search(rhs) or _depth(rhs) <= 0:
        return rhs
    nl = text.find('\n', start)
    parts, depth = [rhs], _depth(rhs)
    for _ in range(LIST_LINES):
        if nl < 0:
            return rhs
        end = text.find('\n', nl + 1)
        line = text[nl + 1:end if end >= 0 else len(text)]
        parts.append(line)
        depth += _depth(line)
        nl = end
        if depth <= 0:
            joined = one_line(parts)
            return joined if any(p.fullmatch(joined) for p in LIST_JOINS) else rhs
    return rhs


def lisp_rhs(text: str, start: int, rest: str):
    """Row 78: the value side of a (def NAME ..) or (define NAME ..) whose rest of line is `rest`, without the
    form's own closing bracket; over several lines (one_line) while a bracket of it is open. None when the
    form does not close by LIST_LINES lines."""
    parts, depth, nl = [rest], _depth(rest), text.find('\n', start)
    for _ in range(LIST_LINES):
        if depth < 0:
            joined = one_line(parts) if len(parts) > 1 else rest.strip()
            return joined[:-1].rstrip() if joined.endswith(')') else None
        if nl < 0:
            return None
        end = text.find('\n', nl + 1)
        line = text[nl + 1:end if end >= 0 else len(text)]
        parts.append(line)
        depth += _depth(line)
        nl = end
    return None


# Row 78: a string that is only interpolated variables: C# and F# $"{a}{b}", Python f"{a}{b}", Nim &"{a}{b}" and
# fmt"{a}{b}", Swift "\\(a)\\(b)", Elixir and Ruby "#{a}#{b}" (a "$a${b}" is read above); with `single`, the
# same in single quotes (Dart, where '$a${b}' interpolates).
_INTERP_NAME = (r'\{[ \t]*([A-Za-z_]\w*)[ \t]*\}|\\\([ \t]*([A-Za-z_]\w*)[ \t]*\)|#\{[ \t]*([A-Za-z_]\w*)[ \t]*\}'
                r'|\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)')
INTERPOLATED = re.compile(r'(?:\$|f|&|fmt)"((?:\{[ \t]*[A-Za-z_]\w*[ \t]*\})+)"'
                          r'|"((?:\\\([ \t]*[A-Za-z_]\w*[ \t]*\))+)"|"((?:#\{[ \t]*[A-Za-z_]\w*[ \t]*\})+)"')
SINGLE_INTERPOLATED = re.compile(r"'((?:\$\{[A-Za-z_]\w*\}|\$[A-Za-z_]\w*(?![\w{]))+)'")
SINGLE_INTERPOLATES = {"dart"}
# Row 78: (format "%s%s" a b) (Clojure) and (format "~a~a" a b) (Racket): a format of nothing but its arguments.
LISP_FORMAT = re.compile(r'\(format[ \t]+"((?:%s|~a)+)"((?:[ \t]+[A-Za-z_][\w-]*)+)[ \t]*\)')


def _literal_rhs(rhs: str, single: bool = False):
    """The _ONE_LITERAL match of a right-hand side that is one literal, or None; an interpolated string
    ("\\(a)\\(b)", "#{a}#{b}", and '${a}' with `single`) is none (row 78)."""
    m = _ONE_LITERAL.fullmatch(rhs)
    if m and ('\\(' in rhs or '#{' in rhs or single and '$' in rhs) and \
            (INTERPOLATED.fullmatch(rhs) or single and SINGLE_INTERPOLATED.fullmatch(rhs)):
        return None
    return m


def _value(rhs: str, known: dict, side: bool = False, single: bool = False):
    """(value, variables used) for an expression of literals, or None: one literal; literals and
    variables of `known` joined by an operator (. .. + & <> *); a string made only of such variables
    ("$a$b": Tcl, Perl, PHP); a list of literals joined with nothing (LIST_JOINS); a Lisp join of literals
    and variables (LISP_ARGS). With `side` (an assignment with white space before its operator, which no
    shell writes), operands with only white space between them are joined too (awk)."""
    m = _literal_rhs(rhs, single)
    if m:
        return (m.group(1) if m.group(1) is not None else m.group(2)), ()
    for pattern in LIST_JOINS:
        m = pattern.fullmatch(rhs)
        if m:
            return _items(next(g for g in m.groups() if g is not None)), ()
    # (Row 78: also unquoted, ${a}${b} and $a$b: a shell assignment, fish's set.)
    m = re.fullmatch(r'"((?:\$\{?[A-Za-z_]\w*\}?)+)"|((?:\$\{[A-Za-z_]\w*\}|\$[A-Za-z_]\w*(?![\w{])){2,})', rhs)
    if m:
        names = [r.group(1) for r in _REF.finditer(m.group(1) or m.group(2))]
        return (''.join(known[n] for n in names), tuple(names)) if all(n in known for n in names) else None
    m = INTERPOLATED.fullmatch(rhs) or (SINGLE_INTERPOLATED.fullmatch(rhs) if single else None)
    if m:
        names = [next(g for g in r.groups() if g) for r in re.finditer(_INTERP_NAME, next(g for g in m.groups() if g))]
        return (''.join(known[n] for n in names), tuple(names)) if all(n in known for n in names) else None
    m = LISP_FORMAT.fullmatch(rhs)
    if m:
        names = m.group(2).split()
        if len(names) * 2 != len(m.group(1)) or not all(n in known for n in names):
            return None
        return ''.join(known[n] for n in names), tuple(names)
    m = LISP_ARGS.fullmatch(rhs)
    if m:
        parts, refs = [], []
        for lit, name in _LISP_ARG.findall(m.group(1)):
            if name:
                if name not in known:
                    return None
                parts.append(known[name])
                refs.append(name)
            else:
                parts.append(lit)
        return (''.join(parts), tuple(refs)) if len(parts) > 1 else None
    m = ARG_JOIN.fullmatch(rhs)
    if m:
        parts, refs = [], []
        for arg in re.split(r'\s*,\s*', m.group(1)):
            lit = _ONE_LITERAL.fullmatch(arg)
            if lit:
                parts.append(lit.group(1) if lit.group(1) is not None else lit.group(2))
            elif re.fullmatch(r'[A-Za-z_]\w*', arg) and arg in known:
                parts.append(known[arg])
                refs.append(arg)
            else:
                return None
        return (''.join(parts), tuple(refs)) if len(parts) > 1 else None
    parts, refs, at = [], [], 0
    while True:
        lit = _ONE_LITERAL.match(rhs, at)
        ref = None if lit else _REF.match(rhs, at)
        if lit:
            parts.append(lit.group(1) if lit.group(1) is not None else lit.group(2))
            at = lit.end()
        elif ref and ref.group(1) in known:
            parts.append(known[ref.group(1)])
            refs.append(ref.group(1))
            at = ref.end()
        else:
            return None
        if at == len(rhs):
            return (''.join(parts), tuple(refs)) if len(parts) > 1 else None
        op = _OP.match(rhs, at) or (_SIDE_OP.match(rhs, at) if side else None)
        if not op:
            return None
        at = op.end()


def _used_glued(text: str, name: str, skip: set) -> bool:
    """Whether `name` is used joined to something (an operator, or another word right against it) on a
    line that does not start at an offset in `skip` (the statements that build its value)."""
    for m in re.finditer(r'\$?\{?\b' + re.escape(name) + r'\b\}?', text):
        line_start = text.rfind('\n', 0, m.start()) + 1
        if line_start in skip:
            continue
        if _tail(USE_GLUE_BEFORE, text, line_start, m.start()) or USE_GLUE_AFTER.match(text, m.end()) \
                or in_join_call(text, m.start(), m.end()) or side_by_side(text, line_start) \
                or interpolated_use(text, *_bare(text, m, name)):
            return True
    return False


def whole_values(text: str, ext=None) -> list:
    """[(value, grade)] of the values the file builds from literals over whole statements, one a line:

      a chain   NAME = "a"; NAME .= "b"; NAME .= "c" (also += &= << ..=, NAME = NAME & "b", append NAME
                "b", set NAME to NAME & "b"): NAME is assigned once, every append adds one literal, all of
                them after the assignment and at its indentation (no append inside a block of its own);
      a join    NAME = $a . $b . "c", NAME = "$a$b": every variable in it assigned once, to one literal or
                a chain;
      a list    NAME = implode('', ['a', 'b']) and the other LIST_JOINS, also over several lines (list_rhs).

    Such a value is WHOLE, as one literal assigned to NAME would be, unless NAME is itself joined to
    something on another line (then PIECE: its value is a piece of a longer one). A value built in any
    other way is not listed, and a value under 24 characters is no material. Row 78: also interpolated
    strings of variables ($"{a}{b}", "\\(a)\\(b)", "#{a}#{b}", and in Dart (`ext`) '${a}${b}' too) and
    (format "%s%s" a b)."""
    if len(text) > 1 << 20:
        return []
    assigns, appends = {}, {}
    for m in APPEND_LINE.finditer(text):
        name = m.group(2) or m.group(3) or m.group(4) or m.group(5)
        appends.setdefault(name, []).append((m.start(), m.group(1), m.group(6)))
    if '<-' in text:
        for m in APPEND_CALL.finditer(text):
            if m.start() not in {a for rows in appends.values() for a, _, _ in rows}:
                appends.setdefault(m.group(2), []).append((m.start(), m.group(1), m.group(3)))
    taken = {a for rows in appends.values() for a, _, _ in rows}
    for pattern, guards in zip(EXTRA_APPENDS, EXTRA_GUARDS):
        if guards and not any(g in text for g in guards):
            continue
        for m in pattern.finditer(text):
            if m.start() not in taken:
                appends.setdefault(m.group(2), []).append((m.start(), m.group(1), m.group(3)))
                taken.add(m.start())
    side = set()
    for m in ASSIGN_LINE.finditer(text):
        if m.start() not in taken:
            assigns.setdefault(m.group(2) or m.group(3), []).append((m.start(), m.group(1), list_rhs(text, m.start(), m.group(4))))
            if m.group(3) and re.search(r'[ \t](?::?=|<-)', text[m.start(3):m.start(4)]):
                side.add(m.start())
    if '(def' in text:
        for m in LISP_ASSIGN.finditer(text):
            if m.start() not in taken:
                rhs = lisp_rhs(text, m.start(), m.group(3))
                if rhs is not None:
                    assigns.setdefault(m.group(2), []).append((m.start(), m.group(1), rhs))
    single = ext is not None and ext_name(ext) in SINGLE_INTERPOLATES
    known, built = {}, {}
    for name, rows in assigns.items():
        if len(rows) != 1:
            continue
        at, indent, rhs = rows[0]
        if not _literal_rhs(rhs, single):
            continue
        value = _value(rhs, {})[0]
        chain = appends.get(name, [])
        if chain:
            if any(a < at or ind != indent or not _ONE_LITERAL.fullmatch(r) for a, ind, r in chain):
                continue
            value += ''.join(_value(r, {})[0] for _, _, r in chain)
            built[name] = (value, {at} | {a for a, _, _ in chain})
        known[name] = value
    out = []
    for name, (value, lines) in built.items():
        out.append((value, PIECE if _used_glued(text, name, lines) else WHOLE))
    for name, rows in assigns.items():
        if len(rows) != 1 or name in appends:
            continue
        at, _, rhs = rows[0]
        if _literal_rhs(rhs, single):
            continue
        got = _value(rhs, known, False, single)
        grade = WHOLE
        if got is None and at in side:
            # Operands side by side (awk) are one value only there; elsewhere they are two arguments, or a
            # literal beside a word: ADJACENT, so that reading() keeps its guard on a join that only
            # lengthens the last value of a plan one of them gives.
            got, grade = _value(rhs, known, True, single), ADJACENT
        if got is not None:
            out.append((got[0], PIECE if _used_glued(text, name, {at}) else grade))
    return [(v, g) for v, g in out if len(v) >= 24]


def candidates(text: str):
    """Yield (how, list_of_byte_values): sources() without the grade."""
    for how, data, _ in sources(text):
        yield how, data


# A literal whose value is a JSON array of 24 or more quoted hex bytes, `["4d","06",...]`.
HEX_ARRAY_RE = re.compile(r'\[\s*(?:(["\'])[0-9A-Fa-f]{1,2}\1\s*,\s*){23,}(["\'])[0-9A-Fa-f]{1,2}\2\s*,?\s*\]')


# Row 101: hex text in pieces of whole bytes with ONE separator between them, the same one throughout
# (`763d337c.6c616e67`, also `-`, `:`, `,` or white space): Day 8's FRAG descriptors.
FRAG_HEX = re.compile(r'[0-9A-Fa-f]{2,}(?:([.\-:,]|[ \t]+)[0-9A-Fa-f]{2,})(?:\1[0-9A-Fa-f]{2,})*')


def string_forms(s, emit, decimal=False, again=True):
    """(how, bytes) for every representation the text `s` reads as. A literal spelled with escapes is
    read for its value: the bytes themselves (escaped_bytes), and, when they are printable text, that
    text under every representation again (`"\\x25\\x38..."` is percent hex)."""
    core = s.strip()
    if re.fullmatch(r'(?:%[0-9A-Fa-f]{2})+', core):
        yield from emit('percent_hex', bytes.fromhex(core.replace('%', '')))
    if re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', core):
        yield from emit('hex_compact', bytes.fromhex(core))
    for d in ':-,.| ;':
        parts = core.split(d)
        if len(parts) >= 24:
            if all(re.fullmatch(r'[0-9A-Fa-f]{1,2}', p) for p in parts):
                yield from emit('hex_' + d, [int(p, 16) for p in parts])
            if all(re.fullmatch(r'\d{1,3}', p) for p in parts):
                yield from emit('decimal_' + d, [int(p) for p in parts])
    if FRAG_HEX.fullmatch(core):                   # row 101: hex in pieces, one separator between them (FRAG)
        d = FRAG_HEX.fullmatch(core).group(1)
        parts = core.split() if d.isspace() else core.split(d)
        if all(len(p) % 2 == 0 for p in parts) and any(len(p) > 2 for p in parts):
            yield from emit('hex_frag_' + (' ' if d.isspace() else d), bytes.fromhex(''.join(parts)))
    arr = HEX_ARRAY_RE.fullmatch(core.replace('\\"', '"'))
    if arr:                                        # "[\"4d\",\"06\",...]": a JSON array of quoted hex bytes (Day 7 Node)
        yield from emit('hex_array', [int(x, 16) for x in re.findall(r'[0-9A-Fa-f]{1,2}', arr.group(0))])
    raw = unescaped(core, decimal) if '\\' in core else None
    if raw:                                        # "\x79\x70...": the literal's value, not its spelling
        yield from emit('escaped_bytes', raw)
        if again and all(32 <= x < 127 for x in raw):
            yield from string_forms(bytes(raw).decode('ascii'), emit, decimal, False)
    for label, t in (('base64', core), ('base64_reversed_text', core[::-1])):
        urlsafe = not B64.match(t) and B64_URLSAFE.match(t)
        if (urlsafe or B64.match(t)) and len(t) % 4 in (0, 2, 3):
            try:
                yield from emit(label.replace('base64', 'base64_urlsafe') if urlsafe else label,
                                base64.b64decode(t.translate(URLSAFE) + '=' * (-len(t) % 4), validate=True))
            except Exception:
                pass


# ---------------------------------------------------------------- more representations (row 57)

_OCTAL = re.compile(r'0o[0-7]{1,3}|0?[0-7]{3}')
_BITS = re.compile(r'(?:0b)?[01]{8}')
_B32 = re.compile(r'[A-Z2-7]+=*|[a-z2-7]+=*')
_NOT_B64 = re.compile(r'[^A-Za-z0-9+/=_-]')        # a character no base64 or hex text holds: base85 is tried
_Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_B85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
_Z85_TO_B85 = str.maketrans(_Z85, _B85)
_B85_TEXT = re.compile(r'[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{25,}')
_A85_TEXT = re.compile(r'(?:<~)?[!-uz]{25,}(?:~>)?')
_Z85_TEXT = re.compile(r'[0-9A-Za-z.\-:+=^!/*?&<>()\[\]{}@%$#]{25,}')
_HEX_TEXT = re.compile(r'[0-9A-Fa-f]+')
_NUMBER_LIST = re.compile(r'[0-9A-Fa-f]{1,3}(?:[:,.|; -][0-9A-Fa-f]{1,3})+')   # a list string_forms reads
MAX_INFLATE = 1 << 20     # bytes a compressed stream may grow to


def _raw(how, data):
    """An `emit` for string_forms that keeps every reading, short ones too."""
    yield how, list(data)


def _direct(core: str):
    """(how, byte values) of the representations row 57 adds, read straight from the text: octal groups
    (`166 075 061`, `0o166,..`), 8-bit binary groups (with a delimiter, or 24 or more groups written
    together), base32 (either case, padded or not), and base85 in its three alphabets (Python's b85,
    Adobe's ascii85, ZeroMQ's z85) when the text holds a character no base64 or hex text does."""
    for d in ' ,:;-.|':
        parts = core.split(d)
        if len(parts) < 24:
            continue
        if all(_OCTAL.fullmatch(p) for p in parts):
            vals = [int(p[2:] if p[:2] == '0o' else p, 8) for p in parts]
            if max(vals) < 256:
                yield 'octal_' + d, vals
        if all(_BITS.fullmatch(p) for p in parts):
            yield 'binary_' + d, [int(p[-8:], 2) for p in parts]
    if len(core) >= 192 and len(core) % 8 == 0 and re.fullmatch(r'[01]+', core):
        yield 'binary_compact', [int(core[i:i + 8], 2) for i in range(0, len(core), 8)]
    if len(core) >= 40 and _B32.fullmatch(core) and len(core.rstrip('=')) % 8 not in (1, 3, 6):
        try:
            t = core.rstrip('=').upper()
            yield 'base32', list(base64.b32decode(t + '=' * (-len(t) % 8)))
        except Exception:  # noqa: BLE001 - not base32 after all
            pass
    b45 = _base45(core)               # Day 26: RFC 9285 text (its SPACE is index 36); the crib and the grammar decide
    if b45 is not None:
        yield 'base45', list(b45)
    if _NOT_B64.search(core) and not _NUMBER_LIST.fullmatch(core):
        for how, alphabet, f in (
                ('base85', _B85_TEXT, lambda t: base64.b85decode(t)),
                ('ascii85', _A85_TEXT, lambda t: base64.a85decode(t, adobe=t.startswith('<~') and t.endswith('~>'))),
                ('z85', _Z85_TEXT, lambda t: base64.b85decode(t.translate(_Z85_TO_B85)))):
            if alphabet.fullmatch(core):
                try:
                    yield how, list(f(core))
                except Exception:  # noqa: BLE001 - not this alphabet
                    pass


_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_TEXT = re.compile(r'[0-9A-Z $%*+\-./:]{40,}')


def _base45(core: str):
    """Base45 (RFC 9285) bytes of a text of at least 40 characters that holds a character no hex or base32 text does,
    else None: three characters give two bytes (at most 65535), a last pair one (at most 255)."""
    if not _B45_TEXT.fullmatch(core) or not re.search(r'[ $%*+\-./:]', core) or len(core) % 3 == 1:
        return None
    v = [_B45.index(c) for c in core]
    out = bytearray()
    for i in range(0, len(v) - 2, 3):
        n = v[i] + v[i + 1] * 45 + v[i + 2] * 2025
        if n > 0xFFFF:
            return None
        out += n.to_bytes(2, 'big')
    if len(v) % 3:
        n = v[-2] + v[-1] * 45
        if n > 0xFF:
            return None
        out.append(n)
    return bytes(out)


def _inflated(data: bytes):
    """(name, bytes) of a zlib or gzip stream (known by its header), or None. Only a stream that
    reaches its end (and so its checksum, which zlib checks) within MAX_INFLATE bytes counts: one
    cut short would give a plan whose last value is cut, under no sign that it was."""
    try:
        if len(data) > 2 and data[0] & 0x0F == 8 and data[0] >> 4 <= 7 and ((data[0] << 8) | data[1]) % 31 == 0:
            name, o = 'zlib', zlib.decompressobj()
        elif data[:3] == b'\x1f\x8b\x08':
            name, o = 'gzip', zlib.decompressobj(31)
        else:
            return None
        out = o.decompress(data, MAX_INFLATE)
        return (name, out) if o.eof else None
    except zlib.error:
        pass
    return None


# Row 92 (2026-10-07): raw (headerless) deflate, as PowerShell's [IO.Compression.DeflateStream], .NET's
# DeflateStream and PHP's gzinflate/gzdeflate write it. No header says it is one, and raw inflate takes many
# random inputs for a while, so a stream counts only when it reaches its end (BFINAL) within MAX_INFLATE bytes
# of output and RAW_RATIO times its input, and its input ends there too: nothing after it, the 4-byte adler32
# of its output (zlib.compress(..)[2:], the header cut off and the trailer kept), or (with `plan_ok`) at most
# RAW_TRAILER bytes when what it gives is a plan. Its input is at most MAX_INFLATE bytes.
RAW_RATIO = 1100          # deflate's own limit is about 1032 to 1
RAW_TRAILER = 8
_RAW = {}


def raw_inflate(data, plan_ok=None):
    """The bytes a raw deflate stream `data` gives (see above), or None."""
    n = len(data)
    if n < 8 or n > MAX_INFLATE or (data[0] >> 1) & 3 == 3:      # block type 3 is no block
        return None
    data = bytes(data)
    if data in _RAW:
        ended = _RAW[data]
    else:
        ended, o = None, zlib.decompressobj(-15)
        try:
            out = o.decompress(data, min(MAX_INFLATE, RAW_RATIO * n))
            if o.eof and len(out) >= 8:
                ended = out, o.unused_data
        except zlib.error:
            pass
        if len(_RAW) > 64:
            _RAW.clear()
        _RAW[data] = ended
    if ended is None:
        return None
    out, rest = ended
    if not rest or rest == zlib.adler32(out).to_bytes(4, 'big'):
        return out
    return out if plan_ok is not None and len(rest) <= RAW_TRAILER and plan_ok(out) else None


def more_forms(s, emit, decimal=False, readings=None, rot13=False):
    """Row 57: (how, bytes) for the representations string_forms does not read, each also when it is a
    compressed stream (zlib or gzip), and one nested level: the readings of string_forms and of this
    whose bytes are printable text read once more, as base64 of hex text or hex of base64 text is
    (`base64+hex_compact`). _sources reads these after every string_forms reading of the file, so a
    reading here never takes the place of an earlier one; it hands over the readings string_forms
    already made of `s` (`readings`), which are not made again."""
    core = s.strip()
    if len(core) < 24:
        return
    # Hex text (most material) reads as none of _direct's representations, binary groups written together aside.
    direct = list(_direct(core)) if not _HEX_TEXT.fullmatch(core) or not core.strip('01') else []
    for how, data in direct:
        yield from emit(how, data)
    if readings is None:
        readings = list(string_forms(core, _raw, decimal, False))
    deflated = []       # row 92: raw deflate streams, emitted after every reading above them
    for how, data in readings + direct:
        if len(data) < 16 or max(data) > 255:
            continue
        raw = bytes(data)
        z = _inflated(raw)
        if z:
            yield from emit(f'{how}+{z[0]}', z[1])
            continue
        r = raw_inflate(raw)
        if r:
            deflated.append((f'{how}+raw_deflate', r))
        if how != 'escaped_bytes' and len(raw) >= 24 and all(32 <= x < 127 for x in raw):
            # (escaped_bytes: string_forms already read that text once more.)
            inner = raw.decode('ascii')
            for ih, idata in list(string_forms(inner, _raw, decimal, False)) + list(_direct(inner)):
                if len(idata) < 16 or max(idata) > 255:
                    continue
                z = _inflated(bytes(idata))
                yield from emit(f'{how}+{ih}' + (f'+{z[0]}' if z else ''), z[1] if z else idata)
                r = None if z else raw_inflate(bytes(idata))
                if r:
                    deflated.append((f'{how}+{ih}+raw_deflate', r))
    for how, data in deflated:
        yield from emit(how, data)
    # Day 9 preparation: the text under ROT13 (letters only), read as the plan's own text and as the base64
    # or hex text it may be. After every reading above, so it takes the place of none of them; the crib and
    # the grammar decide, as for any other reading. Only in a file that names the rotation (`rot13`: the
    # caller's ROT13_HINT), so a file that does not costs nothing.
    if rot13 and _LETTERS.search(core) and len(core) <= MAX_ROT13:
        turned = core.translate(_ROT13)
        if turned[:2] in ('v=', '{"'):
            yield from emit('rot13_text', turned.encode('latin-1', 'replace'))
        for how, data in string_forms(turned, _raw, decimal, False):
            if how in ('base64', 'base64_urlsafe', 'hex_compact', 'base64_reversed_text') and len(data) >= 24:
                yield from emit('rot13+' + how, data)


_LETTERS = re.compile(r'[A-Za-z]')
# What a file that rotates letters by 13 holds: str_rot13, codecs' "rot13"/"rot_13", ROT13(), tr's two tables.
ROT13_HINT = re.compile(r'(?i)rot[_-]?13|N-ZA-M|n-za-m|nopqrstuvwxyzabcdefghijklm')
_ROT13 = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                       'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
MAX_ROT13 = 200_000      # characters of one literal that are read once more under ROT13


# ---------------------------------------------------------------- material from character calls (row 58)

_CHAR_NUM = r'(?:\d{1,3}|0[xX][0-9A-Fa-f]{1,2}|&[Hh][0-9A-Fa-f]{1,2})'
CHAR_ONE = re.compile(r'(?<![\w$>])(?:chr|Chr|CHR|ChrW|chrw|CHRW|ChrB|mb_chr)\s*\(\s*(' + _CHAR_NUM + r')\s*\)'
                      r'|(?<![\w.])(?:string\.char|String\.fromCharCode)\s*\(\s*(' + _CHAR_NUM + r'(?:\s*,\s*' + _CHAR_NUM + r')*)\s*,?\s*\)'
                      r'|(?<![\w.])(\d{1,3})\.chr(?![\w(])'
                      r'|\[char\]\s*(' + _CHAR_NUM + r')')
# What stands between two calls of one run: an operator (. .. + &), a line continuation (VB `_`, `¬`), the
# line end after an operator.
CHAR_SEP = re.compile(r'\s*(?:\.\.|[.+&])(?:[ \t]*[_¬][ \t]*\r?\n)?\s*')


def _char_nums(s: str) -> list:
    """The numbers of a call's argument text, in any separation (`118, 61`, `118 61`, `118uy; 61uy`, `(char)118`)."""
    return [int(n[2:], 16) if n[:2].lower() in ('0x', '&h') else int(n)
            for n in re.findall(r'0[xX][0-9A-Fa-f]+|&[Hh][0-9A-Fa-f]+|\d+', s)]


def char_runs(text: str) -> list:
    """[(byte values, start, end)] of every run of character calls (CHAR_ONE: chr/Chr/ChrW(n),
    string.char(..), String.fromCharCode(..), n.chr, [char]n) joined one to the next by an operator
    (CHAR_SEP), whatever the values: the material spelled one character a call. A run of one call is
    left to the number lists (NUMS_RE)."""
    if 'har' not in text and 'chr' not in text.lower():
        return []
    out, run = [], None
    for m in CHAR_ONE.finditer(text):
        nums = _char_nums(next(g for g in m.groups() if g is not None))
        if run and CHAR_SEP.fullmatch(text, run[2], m.start()):
            run[0].extend(nums)
            run[2] = m.end()
            run[3] += 1
            continue
        if run and run[3] > 1:
            out.append(tuple(run[:3]))
        run = [nums, m.start(), m.end(), 1]
    if run and run[3] > 1:
        out.append(tuple(run[:3]))
    return [(d, a, b) for d, a, b in out if len(d) >= 24 and max(d) < 256]


def char_value(rhs: str):
    """The byte values of a right-hand side that is nothing but character calls (row 58): one run of
    CHAR_ONE calls joined by operators, over one line or several, or one call of CHAR_CALLS (a list of
    numbers in one call: string([]byte{..}), intToUtf8(c(..)), ..); None for anything else. label_plan's
    reading of such a side."""
    s = re.sub(r'[ \t;]+$', '', rhs.strip())
    if not s or ('har' not in s and 'chr' not in s.lower() and 'byte{' not in s and 'intToUtf8' not in s
                 and 'rawToChar' not in s and not _MORE_CALLS.search(s)):
        return None
    nums, at = [], 0
    for m in CHAR_ONE.finditer(s):
        if m.start() != at and not (nums and CHAR_SEP.fullmatch(s, at, m.start())):
            break
        nums += _char_nums(next(g for g in m.groups() if g is not None))
        at = m.end()
    if nums and at == len(s):
        return nums if max(nums) < 256 else None
    for pattern, _ in CHAR_CALLS:
        m = pattern.fullmatch(s)
        if m and m.groups():
            nums = _char_nums(m.group(1))
            return nums if max(nums) < 256 else None
    return None


# ---------------------------------------------------------------- transforms

VERSION_CRIB = re.compile(rb'v=\d\|steps=')
_ROTATED_V = frozenset(((118 << r) | (118 >> (8 - r))) & 255 for r in range(1, 8))
_KEYED = [(n, b'v=1|steps='[n] ^ 118) for n in range(3, 9)]


def _version_start(d) -> bool:
    """Whether `d` can begin `v=<digit>|steps=` under one of undo's transforms. Only the bytes
    every version shares are looked at, so one cheap test spares the cribs of all nine digits
    for a candidate that is no plan (most are)."""
    a, b = d[0], d[1]
    if a ^ b in (75, 61) or (b - a) % 256 == 199 or a in _ROTATED_V:   # identity and xor, rolling xor; add; rotation
        return True
    # A repeating key of length n puts byte n under the key of byte 0 (and, for 2, byte 3 under that of byte 1).
    return b ^ d[3] == 65 or any(a ^ d[n] == x for n, x in _KEYED)


# Row 101: a plan that does not open `v=<n>|steps=` (Day 8: `v=3|language=`; Day 7: `v=1|feature=`). Its
# first field's name is not known, so the crib is a pattern, and only the transforms whose key the first
# byte fixes are tried: identity, one-byte xor, add, rolling xor, a bit rotation, a repeating key of two
# to four bytes (its bytes under the version digit and the bar are tried over the ten digits). A plan that
# opens `steps=` is the fixed cribs' own and is left to them, so nothing read before is read twice.
GRAMMAR_HEAD = re.compile(rb'v=\d+\|(?!steps=)[a-z][a-z0-9_]*=')
HEAD_BYTES = 40


def _undo_general(order, d, n):
    if n < 12:
        return
    a, b = d[0], d[1]
    if a == 118 and b == 61:
        if GRAMMAR_HEAD.match(bytes(d[:HEAD_BYTES])):
            yield order + 'identity', bytes(d)
        return
    k0, k1 = a ^ 118, b ^ 61
    c, e = d[2], d[3]
    # One cheap look at bytes 2 to 5 for each family, before any text is built: most candidates are no plan.
    one = k0 == k1 or (b + 118 - a) % 256 == 61 or a ^ b == 61 or a in _ROTATED_V
    two = e ^ k1 == 124 and 48 <= c ^ k0 <= 57                       # v=<digit>| under a key of two bytes
    three = e ^ k0 == 124                                            # the bar under the key's first byte again
    four = 97 <= d[4] ^ k0 <= 122 and (d[5] ^ k1 == 95 or d[5] ^ k1 == 61 or 97 <= d[5] ^ k1 <= 122 or 48 <= d[5] ^ k1 <= 57)
    if not (one or two or three or four):
        return
    head = bytes(d[:HEAD_BYTES])
    k = a ^ 118
    if b ^ k == 61 and GRAMMAR_HEAD.match(bytes(x ^ k for x in head)):
        yield order + f'xor_{k:02x}', bytes(x ^ k for x in d)
    k = (118 - a) % 256
    if (b + k) % 256 == 61 and GRAMMAR_HEAD.match(bytes((x + k) % 256 for x in head)):
        yield order + f'add_{k}', bytes((x + k) % 256 for x in d)
    if a ^ b == 61 and GRAMMAR_HEAD.match(bytes([118] + [head[i] ^ head[i - 1] for i in range(1, len(head))])):
        yield order + f'rolling_xor_seed_{a ^ 118:02x}', bytes([118] + [d[i] ^ d[i - 1] for i in range(1, n)])
    if a in _ROTATED_V:
        for r in range(1, 8):
            if ((a >> r) | (a << (8 - r))) & 255 == 118 and ((b >> r) | (b << (8 - r))) & 255 == 61:
                if GRAMMAR_HEAD.match(bytes(((x >> r) | (x << (8 - r))) & 255 for x in head)):
                    yield order + f'bit_ror{r}', bytes(((x >> r) | (x << (8 - r))) & 255 for x in d)
    if k0 == k1:
        return                                     # one byte: the xor above
    if two and GRAMMAR_HEAD.match(bytes(x ^ (k1 if i % 2 else k0) for i, x in enumerate(head))):
        yield order + f'repeating_xor_{bytes((k0, k1)).hex()}', bytes(x ^ (k1 if i % 2 else k0) for i, x in enumerate(d))
        return
    for L in (3, 4):
        if not (three if L == 3 else four):
            continue
        for digit in range(48, 58):
            key = [k0, k1, d[2] ^ digit] + ([d[3] ^ 124] if L == 4 else [])
            if GRAMMAR_HEAD.match(bytes(x ^ key[i % L] for i, x in enumerate(head))):
                out = bytes(x ^ key[i % L] for i, x in enumerate(d))
                if looks_like_plan(out):           # ten digits are tried: only a whole plan fixes the key
                    yield order + f'repeating_xor_{bytes(key).hex()}', out
                    return


def undo(data, cribs=None):
    """Yield (transform, bytes) for every transform whose result starts with a crib.

    Perf (Day 27 speed build): the same transforms, tests and yields, in the same order, as _undo_py (the
    reading of before, kept as it was), with each per-byte generator replaced by a C-speed primitive that gives
    the very same bytes (_undo_fast). Taken for a candidate whose values make bytes (bytes, a list of byte
    values, as sources() gives them) and cribs that are bytes; anything else is read by _undo_py exactly."""
    if type(data) is not bytes:
        if not isinstance(data, (bytearray, memoryview, list, tuple)):
            yield from _undo_py(data, cribs)
            return
        try:
            data = bytes(data)
        except (TypeError, ValueError):          # a value that is no byte: the reading of before, as it was
            yield from _undo_py(data, cribs)
            return
    if cribs is not None and not all(type(c) is bytes for c in cribs):
        yield from _undo_py(data, cribs)
        return
    yield from _undo_fast(data, cribs)


# The byte maps undo applies, as 256-byte translate tables (built on first use, kept for the process): with
# `bytes.translate` a whole candidate is mapped in C, to the bytes the per-byte generator gave.
_XOR_TABLES = {}
_ADD_TABLES = {}
_ROR_TABLES = {r: bytes(((x >> r) | (x << (8 - r))) & 255 for x in range(256)) for r in range(1, 8)}
_VERSION_CRIBS = {}      # crib -> whether VERSION_CRIB.fullmatch(crib)


def _xor_table(k: int) -> bytes:
    t = _XOR_TABLES.get(k)
    if t is None:
        t = _XOR_TABLES[k] = bytes(x ^ k for x in range(256))
    return t


def _add_table(k: int) -> bytes:
    t = _ADD_TABLES.get(k)
    if t is None:
        t = _ADD_TABLES[k] = bytes((x + k) % 256 for x in range(256))
    return t


def _xor_key(data: bytes, key) -> bytes:
    """bytes(x ^ key[i % len(key)] for i, x in enumerate(data)), as one big-integer XOR."""
    n = len(data)
    if not n:
        return b''
    key = bytes(key)
    stream = (key * (n // len(key) + 1))[:n]
    return (int.from_bytes(data, 'big') ^ int.from_bytes(stream, 'big')).to_bytes(n, 'big')


def _rolling(d: bytes, seed: int) -> bytes:
    """bytes([seed] + [d[i] ^ d[i - 1] for i in range(1, len(d))]), as one big-integer XOR."""
    n = len(d)
    if n < 2:
        return bytes([seed])
    return bytes([seed]) + (int.from_bytes(d[1:], 'big') ^ int.from_bytes(d[:-1], 'big')).to_bytes(n - 1, 'big')


def _is_version_crib(crib: bytes) -> bool:
    got = _VERSION_CRIBS.get(crib)
    if got is None:
        got = _VERSION_CRIBS[crib] = VERSION_CRIB.fullmatch(crib) is not None
    return got


def _undo_fast(data: bytes, cribs=None):
    """_undo_py for a bytes candidate and bytes cribs: each test and each output by a C-speed primitive.
      identity            d[:m] == crib
      one-byte xor k      x = d[:m] ^ crib (one big-integer XOR) holds k in every byte, k nonzero
      add k               d[:m] mapped by the add-k table is the crib, k nonzero
      rolling xor         d[1:m] ^ d[:m-1] is crib[1:]
      repeating key L     x[L:] == x[:m-L] (x is L-periodic: d[i] ^ x[i % L] == crib[i] for every i < m)
      bit rotation r      d[:m] mapped by the ror-r table is the crib
    and every output is the translate table or the big-integer XOR of the whole candidate."""
    n = len(data)
    for order, d in (('', data), ('reverse+', data[::-1])):
        versions = None
        for crib in (CRIBS if cribs is None else cribs):
            m = len(crib)
            if n < m:
                continue
            is_version = _is_version_crib(crib)
            if is_version:
                if versions is None:
                    versions = _version_start(d)
                if not versions:
                    continue
            head = d[:m]
            if head == crib:
                yield order + 'identity', d
            x = (int.from_bytes(head, 'big') ^ int.from_bytes(crib, 'big')).to_bytes(m, 'big')   # d[i] ^ crib[i]
            k = x[0]
            if k and x.count(k) == m:
                yield order + f'xor_{k:02x}', d.translate(_xor_table(k))
            k = (crib[0] - d[0]) % 256
            if k and (m < 2 or (d[1] + k) % 256 == crib[1]):
                t = _add_table(k)
                if head.translate(t) == crib:
                    yield order + f'add_{k}', d.translate(t)
            # rolling xor: out[i] = d[i] ^ d[i-1], seed = d[0] ^ crib[0]
            if (m < 2 or d[1] ^ d[0] == crib[1]) and \
                    (int.from_bytes(head[1:], 'big') ^ int.from_bytes(head[:-1], 'big')).to_bytes(m - 1, 'big') == crib[1:]:
                yield order + f'rolling_xor_seed_{d[0] ^ crib[0]:02x}', _rolling(d, crib[0])
            # repeating key, length 2..m-2 (at least two crib bytes verify the key)
            for L in range(2, m - 1):
                if x[L:] == x[:m - L]:
                    key = x[:L]
                    out = _xor_key(d, key)
                    # Row 101 (see _undo_py): for this one length the old acceptance alone holds.
                    if L + 2 >= m and is_version and not PLAN_RE.match(out.decode('latin-1')):
                        break
                    yield order + f'repeating_xor_{key.hex()}', out
                    break
            # per-byte bit rotation
            c0, d0 = crib[0], d[0]
            for r in range(1, 8):
                t = _ROR_TABLES[r]
                if t[d0] == c0 and head.translate(t) == crib:
                    yield order + f'bit_ror{r}', d.translate(t)
    # Row 101, after everything above, so that what was read before is read first and as it was.
    for order, d in (('', data), ('reverse+', data[::-1])):
        yield from _undo_general_fast(order, d, n)


def _undo_general_fast(order, d: bytes, n):
    """_undo_general for a bytes candidate, each transform by a C-speed primitive (see _undo_fast)."""
    if n < 12:
        return
    a, b = d[0], d[1]
    if a == 118 and b == 61:
        if GRAMMAR_HEAD.match(d[:HEAD_BYTES]):
            yield order + 'identity', d
        return
    k0, k1 = a ^ 118, b ^ 61
    c, e = d[2], d[3]
    # One cheap look at bytes 2 to 5 for each family, before any text is built: most candidates are no plan.
    one = k0 == k1 or (b + 118 - a) % 256 == 61 or a ^ b == 61 or a in _ROTATED_V
    two = e ^ k1 == 124 and 48 <= c ^ k0 <= 57                       # v=<digit>| under a key of two bytes
    three = e ^ k0 == 124                                            # the bar under the key's first byte again
    four = 97 <= d[4] ^ k0 <= 122 and (d[5] ^ k1 == 95 or d[5] ^ k1 == 61 or 97 <= d[5] ^ k1 <= 122 or 48 <= d[5] ^ k1 <= 57)
    if not (one or two or three or four):
        return
    head = d[:HEAD_BYTES]
    k = a ^ 118
    if b ^ k == 61:
        t = _xor_table(k)
        if GRAMMAR_HEAD.match(head.translate(t)):
            yield order + f'xor_{k:02x}', d.translate(t)
    k = (118 - a) % 256
    if (b + k) % 256 == 61:
        t = _add_table(k)
        if GRAMMAR_HEAD.match(head.translate(t)):
            yield order + f'add_{k}', d.translate(t)
    if a ^ b == 61 and GRAMMAR_HEAD.match(_rolling(head, 118)):
        yield order + f'rolling_xor_seed_{a ^ 118:02x}', _rolling(d, 118)
    if a in _ROTATED_V:
        for r in range(1, 8):
            if ((a >> r) | (a << (8 - r))) & 255 == 118 and ((b >> r) | (b << (8 - r))) & 255 == 61:
                t = _ROR_TABLES[r]
                if GRAMMAR_HEAD.match(head.translate(t)):
                    yield order + f'bit_ror{r}', d.translate(t)
    if k0 == k1:
        return                                     # one byte: the xor above
    if two and GRAMMAR_HEAD.match(_xor_key(head, (k0, k1))):
        yield order + f'repeating_xor_{bytes((k0, k1)).hex()}', _xor_key(d, (k0, k1))
        return
    for L in (3, 4):
        if not (three if L == 3 else four):
            continue
        for digit in range(48, 58):
            key = [k0, k1, d[2] ^ digit] + ([d[3] ^ 124] if L == 4 else [])
            if GRAMMAR_HEAD.match(_xor_key(head, key)):
                out = _xor_key(d, key)
                if looks_like_plan(out):           # ten digits are tried: only a whole plan fixes the key
                    yield order + f'repeating_xor_{bytes(key).hex()}', out
                    return


def _undo_py(data, cribs=None):
    """undo's reading as it was before the Day 27 speed build: every candidate undo does not take to
    _undo_fast (and the reference the speed build's differential test holds _undo_fast against)."""
    n = len(data)
    for order, d in (('', data), ('reverse+', data[::-1])):
        versions = None
        for crib in (CRIBS if cribs is None else cribs):
            m = len(crib)
            if n < m:
                continue
            if VERSION_CRIB.fullmatch(crib):
                if versions is None:
                    versions = _version_start(d)
                if not versions:
                    continue
            if bytes(d[:m]) == crib:
                yield order + 'identity', bytes(d)
            k = d[0] ^ crib[0]
            if k and all(d[i] ^ k == crib[i] for i in range(m)):
                yield order + f'xor_{k:02x}', bytes(x ^ k for x in d)
            k = (crib[0] - d[0]) % 256
            if k and all((d[i] + k) % 256 == crib[i] for i in range(m)):
                yield order + f'add_{k}', bytes((x + k) % 256 for x in d)
            # rolling xor: out[i] = d[i] ^ d[i-1], seed = d[0] ^ crib[0]
            if all(d[i] ^ d[i - 1] == crib[i] for i in range(1, m)):
                yield order + f'rolling_xor_seed_{d[0] ^ crib[0]:02x}', bytes([crib[0]] + [d[i] ^ d[i - 1] for i in range(1, n)])
            # repeating key, length 2..m-2 (at least two crib bytes verify the key)
            for L in range(2, m - 1):
                key = [d[i] ^ crib[i] for i in range(L)]
                if all(d[i] ^ key[i % L] == crib[i] for i in range(L, m)):
                    out = bytes(x ^ key[i % L] for i, x in enumerate(d))
                    # Row 101. A key as long as the crib without two bytes has its byte under the version
                    # digit fixed by nothing but the crib's own digit: the crib of ANOTHER digit gives the
                    # same key one byte off, and a text that is the plan with every L-th byte changed
                    # (`v=9|steps=..|adkpter=..`). PLAN_RE refuses that; the looser grammar would not, so
                    # for this one length the old acceptance alone holds.
                    if L + 2 >= m and VERSION_CRIB.fullmatch(crib) and not PLAN_RE.match(out.decode('latin-1')):
                        break
                    yield order + f'repeating_xor_{bytes(key).hex()}', out
                    break
            # per-byte bit rotation
            for r in range(1, 8):
                if all((((d[i] >> r) | (d[i] << (8 - r))) & 255) == crib[i] for i in range(m)):
                    yield order + f'bit_ror{r}', bytes(((x >> r) | (x << (8 - r))) & 255 for x in d)
    # Row 101, after everything above, so that what was read before is read first and as it was.
    for order, d in (('', data), ('reverse+', data[::-1])):
        yield from _undo_general(order, d, n)


def recover(text: str, ext=None, extra_cribs=()):
    """Return (plan_text, representation, transform) or None.

    `ext` adds the cribs of hooks_<ext>.py, `extra_cribs` adds the caller's own; both are tried
    after the built-in ones, so a hook can never change what is recovered today."""
    cribs = None
    extra = [bytes(c) for c in extra_cribs or () if isinstance(c, (bytes, bytearray)) and len(c) >= 2]
    if ext is not None:
        extra += hooks(ext)[0]
    if extra:
        cribs = CRIBS + [c for c in extra if c not in CRIBS]
    for how, data in candidates(text):
        for tr, out in undo(data, cribs):
            t = looks_like_plan(out)
            if t:
                return t, how, tr
    return None


def plain_fragments(text: str):
    """Batch also carries the plan in clear, as numbered set-fragments."""
    frags = {}
    for m in re.finditer(r'(?im)^\s*set\s+"?([A-Za-z_]\w*?)(\d+)=(.*?)"?\s*(?:&\s*rem\b.*)?\r?$', text):
        frags.setdefault(m.group(1).lower(), {})[int(m.group(2))] = m.group(3)
    best = max(frags.values(), key=len, default={})
    return ''.join(best[i] for i in sorted(best))


# ---------------------------------------------------------------- what callers read

def flatten(plan_text: str) -> dict:
    """The plan as one flat {key: value} table.

    `k=v|k=v` reads as written. A JSON descriptor keeps its scalars; a list becomes its items
    joined with commas (steps), and a nested object's members are lifted to the top unless a
    top-level key of that name exists (JScript keeps the indicators under `values`)."""
    if not plan_text:
        return {}
    if plan_text.startswith('{'):
        try:
            d = json.loads(plan_text)
        except ValueError:
            return {}
        if not isinstance(d, dict):
            return {}
        plan, nested = {}, []
        for k, v in d.items():
            if isinstance(v, dict):
                nested.append(v)
            elif isinstance(v, list):
                plan[k] = ','.join(x if isinstance(x, str) else json.dumps(x, separators=(",", ":")) for x in v)
            else:
                plan[k] = v
        for inner in nested:
            for k, v in inner.items():
                plan.setdefault(k, v)
        return plan
    plan = {}
    for part in plan_text.split('|'):
        k, sep, v = part.partition('=')
        if sep:
            plan.setdefault(k, v)
    return plan


def graded_plans(text: str, ext=None) -> list:
    """Every plan the file decodes to, as [(plan text, representation, transform, grade)] in the
    order recover tries them, each plan text once, with the best grade of the sources that
    gave it (see sources).

    One grade is settled here, where it is known what each literal decodes to: a plan whose
    every whole source is a string literal beside a like literal (the same alphabet, at least
    half its length) that is no plan by itself is a PIECE. Such neighbours are the chunks of
    one material, whatever stands between them and in whatever order (one variable per chunk,
    each chunk encoded on its own). A shorter neighbour (an alphabet, a key, a name) is not
    one, and neither is a second copy of the plan."""
    return _graded_plans(text, ext)[0]


def _graded_plans(text: str, ext=None):
    """(graded_plans(), raw, fold): raw maps each plan read from the file's own text to the strings it
    was read from (None for numbers), fold the same for the text with its character calls folded."""
    cribs = None
    extra = hooks(ext)[0] if ext is not None else []
    if extra:
        cribs = CRIBS + [c for c in extra if c not in CRIBS]
    raw, fold, cont = {}, {}, set()
    out = _graded(text, cribs, ext, raw, cont)
    folded = fold_char_calls(text, ext)
    if folded != text:
        # The same file with its character calls written as the literals they return: a plan read there
        # counts with the grade it has there (a join that a call began is whole once the call is read).
        at = {p[0]: i for i, p in enumerate(out)}
        for p in _graded(folded, cribs, ext, fold, cont):
            if p[0] not in at:
                at[p[0]] = len(out)
                out.append(p)
            elif p[3] > out[at[p[0]]][3]:
                out[at[p[0]]] = out[at[p[0]]][:3] + (p[3],)
    _bounded_put(_CONTINUED, (ext, text), frozenset(cont))
    return out, raw, fold


# Day 27 (script residuals): the plans of a text that _graded found GOING ON past the literal they were read from (a
# rest of it in a place TAILS or the head rule reads), by (ext, text); bounded.
_CONTINUED = {}


def continued_plans(text: str, ext=None) -> frozenset:
    """The plan texts of `text` read from a literal whose rest stands where TAILS or HEAD_PIECES reads one (a literal
    behind it that decodes on from it; another value of its dict, a keyed write to its container, a related name, a
    function's return). generic.by_label takes no codec label's plan whole over such a plan, and shapes_py and lang_sh
    none from such a literal: it is that very piece. A plan graded PIECE for another reason (a run of like literals,
    code glued to it) is listed only when such a rest stands there too: without one the codec label settles it as
    before (Day 6 to 9's `'..''..'` shell words, 150 saved members, each read whole by the label)."""
    key = (ext, text)
    if key not in _CONTINUED:
        reading(text, ext)               # through reading()'s cache, as longest() does
        if key not in _CONTINUED:
            _graded_plans(text, ext)
    return _CONTINUED.get(key, frozenset())


# Calls that return the characters of their numbers, in the languages a specimen may be written in:
# chr(118) (PHP, Perl, Python), Chr/ChrW (VBScript, AutoIt), string.char(118, 61) (Lua),
# String.fromCharCode(118, 61) (JScript), 118.chr and [118, 61].pack('C*') (Ruby),
# (ASCII character 118) / (character id 118) (AppleScript), "".join(map(chr, (118, 61))) (Python):
# each is written as a quoted literal.
# [format %c 118] (Tcl) stands inside a word, and is written as the character itself. A cast,
# (char) 118 in Java or Groovy and [char]118 in PowerShell, is not one: two casts added are a number.
_NUMS = r'(\d{1,3}(?:\s*,\s*\d{1,3})*)'
CHAR_CALLS = [
    (re.compile(r'(?<![\w.$])(?:chr|Chr|CHR|ChrW|chrw|ChrB|mb_chr)\s*\(\s*(\d{1,3}|0[xX][0-9A-Fa-f]{1,2})\s*\)'), '"'),
    (re.compile(r'(?<![\w.])string\.char\s*\(\s*' + _NUMS + r'\s*\)'), '"'),
    (re.compile(r'(?<![\w.])String\.fromCharCode\s*\(\s*' + _NUMS + r'\s*\)'), '"'),
    (re.compile(r'(?<![\w.])(\d{1,3})\.chr(?![\w(])'), '"'),
    (re.compile(r'\[\s*' + _NUMS + r'\s*\]\.pack\(\s*[\'"][CcU]\*[\'"]\s*\)'), '"'),
    (re.compile(r'\(\s*(?:ASCII character|character id)\s+(\d{1,3})\s*\)'), '"'),
    (re.compile(r'\[format\s+%c\s+(\d{1,3})\]'), ''),
    (re.compile(r'(?:\'\'|"")\.join\(\s*map\(\s*chr\s*,\s*[\[(]\s*' + _NUMS + r'\s*,?\s*[\])]\s*\)\s*\)'), '"'),
    # Row 71: string([]byte{118, 61}) (Go), intToUtf8(c(118, 61)) and rawToChar(as.raw(c(..))) (R),
    # (-join [char[]](118, 61)) (PowerShell).
    (re.compile(r'(?<![\w.])string\(\s*\[\]byte\{\s*' + _NUMS + r'\s*,?\s*\}\s*\)'), '"'),
    (re.compile(r'(?<![\w.])intToUtf8\(\s*c\(\s*' + _NUMS + r'\s*\)\s*\)'), '"'),
    (re.compile(r'(?<![\w.])rawToChar\(\s*as\.raw\(\s*c\(\s*' + _NUMS + r'\s*\)\s*\)\s*\)'), '"'),
    (re.compile(r'\(\s*-join\s*\[char\[\]\]\s*\(\s*' + _NUMS + r'\s*\)\s*\)'), '"'),
]
# Row 78: the character calls of fifteen more languages, each one call that RETURNS a string (a cast such as
# (char) 118 or Char(118) alone stays a number or a character, and is read only inside a call that makes a
# string of it). Composite calls stand before the single ones they contain.
_NUMS_BR = r'(\d{1,3}(?:\s*,\s*\d{1,3})*)\s*,?'                    # a C-family initializer: a comma may end it
_NUMS_SP = r'(\d{1,3}(?:[\s,]+\d{1,3})*)'                          # a Lisp vector or list: white space between
_CAST_LIST = r'((?:\(char\)\s*\d{1,3}\s*,\s*)*\(char\)\s*\d{1,3})\s*,?'   # (char)118, (char)61 (C#)
_CHARS_OF = r'((?:Char\(\s*\d{1,3}\s*\)\s*,\s*)*Char\(\s*\d{1,3}\s*\))'      # Char(118), Char(61) (Kotlin)
MORE_CHAR_CALLS = [
    # C#: new string(new[] { (char)118, .. }), Encoding.ASCII.GetString(new byte[] { 118, .. }),
    # ((char)118).ToString(), char.ConvertFromUtf32(118).
    (re.compile(r'\bnew\s+string\(\s*new\s*(?:char\s*)?\[\s*\]\s*\{\s*' + _CAST_LIST + r'\s*\}\s*\)'), '"'),
    (re.compile(r'\bnew\s+string\(\s*new\s+char\s*\[\s*\]\s*\{\s*' + _NUMS_BR + r'\s*\}\s*\)'), '"'),
    (re.compile(r'(?<![\w.])(?:System\.)?(?:Text\.)?Encoding\.(?:ASCII|UTF8|Latin1|Default)\.GetString\(\s*new\s*(?:byte\s*)?'
                r'\[\s*\]\s*\{\s*' + _NUMS_BR + r'\s*\}\s*\)'), '"'),
    (re.compile(r'\(\s*\(char\)\s*(\d{1,3})\s*\)\.ToString\(\)'), '"'),
    (re.compile(r'(?<![\w.])char\.ConvertFromUtf32\(\s*(\d{1,3})\s*\)'), '"'),
    # F#: Encoding.ASCII.GetString [| 118uy; .. |], String(Array.map char [| 118; .. |]), string (char 118).
    (re.compile(r'(?<![\w.])(?:System\.)?(?:Text\.)?Encoding\.(?:ASCII|UTF8|Latin1|Default)\.GetString\s*\(?\s*\[\|\s*'
                r'((?:\d{1,3}uy\s*;\s*)*\d{1,3}uy)\s*;?\s*\|\]\s*\)?'), '"'),
    (re.compile(r'(?<![\w.])(?:System\.)?String\s*\(\s*Array\.map\s+char\s+\[\|\s*((?:\d{1,3}\s*;\s*)*\d{1,3})\s*;?\s*\|\]\s*\)'), '"'),
    (re.compile(r'(?<![\w.])string\s*\(\s*char\s+(\d{1,3})\s*\)'), '"'),
    # Swift: String(decoding: [..] as [UInt8], as: UTF8.self), String(bytes: [..], encoding: .utf8)!,
    # String(UnicodeScalar(UInt8(118))) and String(Character(UnicodeScalar(UInt8(118)))).
    (re.compile(r'(?<![\w.])String\(\s*decoding:\s*\[\s*' + _NUMS_BR + r'\s*\](?:\s*as\s*\[UInt8\])?\s*,\s*as:\s*UTF8\.self\s*\)'), '"'),
    (re.compile(r'(?<![\w.])String\(\s*bytes:\s*\[\s*' + _NUMS_BR + r'\s*\](?:\s*as\s*\[UInt8\])?\s*,\s*encoding:\s*'
                r'(?:String\.Encoding)?\.(?:utf8|ascii)\s*\)!?'), '"'),
    (re.compile(r'(?<![\w.])String\(\s*UnicodeScalar\(\s*UInt8\(\s*(\d{1,3})\s*\)\s*\)\s*\)'), '"'),
    (re.compile(r'(?<![\w.])String\(\s*Character\(\s*UnicodeScalar\(\s*UInt8\(\s*(\d{1,3})\s*\)\s*\)\s*\)\s*\)'), '"'),
    # Kotlin: String(charArrayOf(Char(118), ..)), byteArrayOf(..).decodeToString(), String(byteArrayOf(..)),
    # Char(118).toString(), 118.toChar().toString().
    (re.compile(r'(?<![\w.])String\(\s*charArrayOf\(\s*' + _CHARS_OF + r'\s*\)\s*\)'), '"'),
    (re.compile(r'(?<![\w.])byteArrayOf\(\s*' + _NUMS + r'\s*\)\.decodeToString\(\)'), '"'),
    (re.compile(r'(?<![\w.])String\(\s*byteArrayOf\(\s*' + _NUMS + r'\s*\)\s*(?:,\s*Charsets\.\w+\s*)?\)'), '"'),
    (re.compile(r'(?<![\w.])Char\(\s*(\d{1,3})\s*\)\.toString\(\)'), '"'),
    (re.compile(r'(?<![\w.])(\d{1,3})\.toChar\(\)\.toString\(\)'), '"'),
    # Dart: String.fromCharCodes([..]), utf8.decode([..]) and ascii.decode([..]).
    (re.compile(r'(?<![\w.])String\.fromCharCodes\(\s*\[\s*' + _NUMS_BR + r'\s*\]\s*\)'), '"'),
    (re.compile(r'(?<![\w.])(?:utf8|ascii|latin1)\.decode\(\s*\[\s*' + _NUMS_BR + r'\s*\]\s*\)'), '"'),
    # Julia: String(UInt8[..]), and Char(118), which * joins to a string.
    (re.compile(r'(?<![\w.])String\(\s*UInt8\[\s*' + _NUMS_BR + r'\s*\]\s*\)'), '"'),
    (re.compile(r'(?<![\w.])Char\(\s*(\d{1,3})\s*\)(?=\s*\*|\s*$|\s*\r?\n)'), '"'),
    # Elixir: <<118, 61>>, List.to_string([..]).
    (re.compile(r'<<\s*' + _NUMS + r'\s*>>'), '"'),
    (re.compile(r'(?<![\w.])List\.to_string\(\s*\[\s*' + _NUMS + r'\s*\]\s*\)'), '"'),
    # Clojure: (apply str (map char [..])), (String. (byte-array [..])), (char 118) inside a (str ..).
    (re.compile(r'\(apply\s+str\s+\(map\s+char\s+\[\s*' + _NUMS_SP + r'\s*\]\s*\)\s*\)'), '"'),
    (re.compile(r'\(String\.\s+\(byte-array\s+\[\s*' + _NUMS_SP + r'\s*\]\s*\)\s*\)'), '"'),
    (re.compile(r'\(char\s+(\d{1,3})\)'), '"'),
    # Scheme, Racket: (list->string (map integer->char '(..))), (string (integer->char 118) ..),
    # (bytes->string/utf-8 (bytes ..)).
    (re.compile(r"\(list->string\s+\(map\s+integer->char\s+'\(\s*" + _NUMS_SP + r"\s*\)\s*\)\s*\)"), '"'),
    (re.compile(r'\(string((?:\s+\(integer->char\s+\d{1,3}\))+)\s*\)'), '"'),
    (re.compile(r'\(bytes->string/(?:utf-8|latin-1)\s+\(bytes\s+' + _NUMS_SP + r'\s*\)\s*\)'), '"'),
    # Nim: $chr(118), a string (chr(118) alone is a char, which & joins to a string as well).
    (re.compile(r'\$chr\(\s*(\d{1,3})\s*\)'), '"'),
    # Java: String.valueOf(new char[] { .. }), new String(new byte[] { .. }, ..), new String(new char[] { .. }),
    # Character.toString(118), String.valueOf((char) 118).
    (re.compile(r'(?<![\w.])String\.valueOf\(\s*new\s+char\s*\[\s*\]\s*\{\s*' + _NUMS_BR + r'\s*\}\s*\)'), '"'),
    (re.compile(r'\bnew\s+String\(\s*new\s+(?:byte|char)\s*\[\s*\]\s*\{\s*' + _NUMS_BR
                + r'\s*\}\s*(?:,\s*(?:(?:java\.nio\.charset\.)?StandardCharsets\.\w+|"[\w-]+"))?\s*\)'), '"'),
    (re.compile(r'(?<![\w.])Character\.toString\(\s*(?:\(char\)\s*)?(\d{1,3})\s*\)'), '"'),
    (re.compile(r'(?<![\w.])String\.valueOf\(\s*\(char\)\s*(\d{1,3})\s*\)'), '"'),
]
CHAR_CALLS += MORE_CHAR_CALLS
# What a text must hold for each of MORE_CHAR_CALLS to be tried at all (one substring each, in its order): a
# solve folds every file, and most files hold none of them.
MORE_GUARDS = ('new string', 'new string', 'GetString', 'ToString', 'ConvertFromUtf32', 'GetString', 'Array.map',
               '(char ', 'decoding:', 'bytes:', 'UnicodeScalar', 'UnicodeScalar', 'charArrayOf', 'decodeToString',
               'byteArrayOf', 'Char(', 'toChar', 'fromCharCodes', 'decode([', 'UInt8[', 'Char(', '>>',
               'List.to_string', 'map char', 'byte-array', '(char ', 'list->string', 'integer->char', 'bytes->string',
               '$chr', 'valueOf', 'new String', 'Character.', 'valueOf')
assert len(MORE_GUARDS) == len(MORE_CHAR_CALLS)
# Perf (Day 27 speed build): the same for the first calls of CHAR_CALLS, a text each of them cannot match without
# (any one of the tuple: chr/Chr/ChrW/chrw/ChrB/mb_chr hold "hr", CHR holds "HR"; each other a literal of its
# pattern). Asked of the text as it stands at that call, so a call that is skipped is one that matches nothing.
BASE_GUARDS = (('hr', 'HR'), ('string.char',), ('String.fromCharCode',), ('.chr',), ('].pack(',), ('character',),
               ('[format',), ('.join(',), ('[]byte{',), ('intToUtf8(',), ('rawToChar(',), ('[char[]]',))
assert len(BASE_GUARDS) == len(CHAR_CALLS) - len(MORE_CHAR_CALLS)
_MORE_CALLS = re.compile(r'string\(|String\(|Encoding\.|ConvertFromUtf32|charArrayOf|byteArrayOf|toChar|Char\(|fromCharCodes'
                         r'|\.decode\(|UInt8\[|<<\s*\d|List\.to_string|\(char |byte-array|integer->char|bytes->string|\$chr'
                         r'|valueOf|Character\.|map\s+char')
# Row 78: printf in a command substitution, $(printf '\166\075') or (printf '\x76') (zsh, bash, fish), and
# awk's sprintf("%c%c", 118, 61): their text as the literal it prints.
PRINTF_CALL = re.compile(r"(\")?\$?\(\s*printf\s+'((?:\\[0-7]{3}|\\x[0-9A-Fa-f]{2})+)'\s*\)(?(1)\")")
# Row 78: fish reads \xHH escapes outside quotes, so a word may start with them: \x76\x3d"..".
FISH_ESCAPES = re.compile(r"(?<=[ \t])((?:\\x[0-9A-Fa-f]{2})+)(?=[\"'])")
SPRINTF_CALL = re.compile(r'(?<![\w.])sprintf\(\s*"((?:%c)+)"\s*,\s*' + _NUMS + r'\s*\)')
_UNSAFE = set('"\'\\$[]{}`')


# Day 9 preparation (2026-10-08): two more calls that are written out as the literal they return.
# A format of nothing but placeholders over literal arguments: PowerShell's "{1}{0}" -f 'b','a', Python's
# "{}{}".format('a', 'b') and "{0}{1}".format(..), String.Format("{0}{1}", "a", "b"), sprintf("%s%s", "a", "b")
# (also Sprintf, format!). Every placeholder must name an argument that is there.
_ARG = r'(?:"[^"\r\n\\$`]*"|\'[^\'\r\n\\]*\')'
_ARGS = r'(' + _ARG + r'(?:\s*,\s*' + _ARG + r')*)'
FORMAT_CALLS = [
    re.compile(r'\(?\s*(["\'])((?:\{\d{1,2}\})+)\1\s*-f\s*' + _ARGS + r'\s*\)?'),
    re.compile(r'(["\'])((?:\{\d{0,2}\})+)\1\.format\(\s*' + _ARGS + r'\s*\)'),
    re.compile(r'(?<![\w.])(?:[Ss]tring|String)\.Format\(\s*(")((?:\{\d{1,2}\})+)"\s*,\s*' + _ARGS + r'\s*\)'),
    re.compile(r'(?<![\w.])(?:fmt\.Sprintf|sprintf|format!?)\(\s*(")((?:%s|\{\})+)"\s*,\s*' + _ARGS + r'\s*\)'),
]
# A marker taken out of a literal: 'ab@@cd'.Replace('@@', ''), .replaceAll, .gsub, -replace '@@','' and PHP's
# str_replace('@@', '', 'ab@@cd'). The marker is one to eight characters that no pattern language reads
# specially. A lower-case .replace( takes out every marker in Python and only the first in JavaScript, so it
# is written out only when the literal holds the marker once.
_MARKER = r'(["\'])([A-Za-z0-9@#!~_%&:;,<>=-]{1,8})'      # followed by the back-reference to its quote
_EMPTY2 = r'(?:\'\'|"")'
REPLACE_AFTER = re.compile(r'(["\'])([^"\'\r\n\\$`]{24,})\1\s*(?:\.(Replace|replaceAll|replace|gsub|delete)\(\s*'
                           + _MARKER + r'\4\s*(?:,\s*' + _EMPTY2 + r')?\s*\)|(-replace)\s*'
                           + _MARKER + r'\7\s*(?:,\s*' + _EMPTY2 + r')?)')
REPLACE_BEFORE = re.compile(r'(?<![\w.])str_replace\(\s*' + _MARKER + r'\1\s*,\s*' + _EMPTY2
                            + r'\s*,\s*(["\'])([^"\'\r\n\\$`]{24,})\3\s*\)')


def fold_formats(text: str) -> str:
    """The text with every format of literals (FORMAT_CALLS) and every marker removal (REPLACE_AFTER,
    REPLACE_BEFORE) written as the one literal it returns; anything it cannot work out is left as it was."""
    def literal(value, m):
        return m.group(0) if _UNSAFE & set(value) or not value.isprintable() else '"' + value + '"'

    def formatted(m):
        args = [x[1:-1] for x in re.findall(_ARG, m.group(3))]
        slots = re.findall(r'\{(\d*)\}|(%s)', m.group(2))
        if all(s[0] == '' for s in slots):
            order = list(range(len(slots)))                   # {} {} or %s %s: in the order written
        elif all(s[0] != '' for s in slots):
            order = [int(s[0]) for s in slots]
        else:
            return m.group(0)
        if not order or max(order) >= len(args) or (all(s[0] == '' for s in slots) and len(order) != len(args)):
            return m.group(0)
        return literal(''.join(args[i] for i in order), m)

    def removed(value, marker, how, m):
        if not marker or marker not in value:
            return m.group(0)
        if how == 'delete' and len(marker) != 1:              # Ruby's delete takes out characters, not a text
            return m.group(0)
        if how == 'replace' and value.count(marker) != 1:
            return m.group(0)
        return literal(value.replace(marker, ''), m)

    if '-f' in text or 'ormat' in text or 'printf' in text:
        for pattern in FORMAT_CALLS:
            text = pattern.sub(formatted, text)
    if 'eplace' in text or 'gsub' in text or '.delete(' in text:
        text = REPLACE_AFTER.sub(lambda m: removed(m.group(2), m.group(5) or m.group(8), m.group(3) or 'Replace', m), text)
        text = REPLACE_BEFORE.sub(lambda m: removed(m.group(4), m.group(2), 'Replace', m), text)
    return text


def fold_char_calls(text: str, ext=None) -> str:
    """The text with every character call (CHAR_CALLS) written as what it returns, or the text as it
    is. A call whose characters are not printable ASCII, or are a quote, a backslash or a character
    that starts an expansion, is left as it was. Row 78: also printf in a command substitution and
    awk's sprintf("%c.."), and in a fish script (`ext`) the \\xHH escapes a word starts with."""
    text = fold_formats(text)
    more = _MORE_CALLS.search(text) is not None
    printf = 'printf' in text
    if ext is not None and ext_name(ext) == 'fish' and '\\x' in text:
        text = FISH_ESCAPES.sub(lambda m: '"' + bytes(unescaped(m.group(1)) or b'').decode('latin-1') + '"'
                                if all(32 <= x < 127 and chr(x) not in _UNSAFE for x in unescaped(m.group(1)) or [0])
                                else m.group(0), text)
    if not more and not printf and 'har' not in text and 'chr' not in text.lower() and '%c' not in text \
            and 'byte{' not in text and 'intToUtf8' not in text and 'rawToChar' not in text:
        return text

    def written(m, nums, quote='"'):
        chars = ''.join(map(chr, nums))
        if not nums or not all(32 <= n < 127 for n in nums) or _UNSAFE & set(chars):
            return m.group(0)
        return quote + chars + quote
    first = len(CHAR_CALLS) - len(MORE_CHAR_CALLS)
    for i, (pattern, quote) in enumerate(CHAR_CALLS):
        if i >= first and (not more or MORE_GUARDS[i - first] not in text):
            continue
        if i < first and not any(g in text for g in BASE_GUARDS[i]):
            continue                    # perf (Day 27): no text the call needs, so no match (the text as it stands)

        def lit(m, quote=quote):
            return written(m, _char_nums(next((g for g in m.groups() if g is not None), '')), quote)
        text = pattern.sub(lit, text)
    if printf:
        text = PRINTF_CALL.sub(lambda m: written(m, unescaped(m.group(2)) or []), text)
        text = SPRINTF_CALL.sub(lambda m: written(m, _char_nums(m.group(2)))
                                if len(m.group(1)) // 2 == len(_char_nums(m.group(2))) else m.group(0), text)
    return text


def _graded(text: str, cribs, ext, srcs=None, cont=None) -> list:
    """graded_plans() of one text; srcs, when given, gets {plan text: the strings it was read from}, and cont the
    plan texts TAILS or HEAD_PIECES graded PIECE (continued_plans)."""
    lits = _literals(text)
    out, at, whole, gave, src_of = [], {}, {}, set(), {}
    for how, data, grade, s in _sources(text, lits, cribs, ext):
        for tr, raw in undo(data, cribs):
            t = looks_like_plan(raw)
            if not t:
                continue
            gave.add(s)
            if srcs is not None:
                srcs.setdefault(t, set()).add(s)
            again = None if t.startswith('{') else PLAN_START.search(t, 1)
            if again:                              # two copies in one candidate: the first ends where the second begins
                t = t[:again.start()]
            if cont is not None and isinstance(s, str):
                src_of.setdefault(t, set()).add(s)
            if t not in at:
                at[t] = len(out)
                out.append((t, how, tr, grade))
            elif grade > out[at[t]][3]:
                out[at[t]] = out[at[t]][:3] + (grade,)
            if grade == WHOLE:
                whole.setdefault(t, set()).add(s)
    kinds = {s: k for _, _, s, k in lits if k}
    for value, _, _, _ in block_literals(text):   # a block is a literal of its alphabet too (review of row 56)
        k = _alphabet(value)
        if k:
            kinds.setdefault(value, k)
    longest = {}                                   # alphabet -> the longest literal of it that is no plan by itself
    for s, k in kinds.items():
        if s not in gave and len(s) > longest.get(k, 0):
            longest[k] = len(s)
    for t, of in whole.items():
        if all(s in kinds and 2 * longest.get(kinds[s], 0) >= len(s) for s in of):
            out[at[t]] = out[at[t]][:3] + (PIECE,)
    if TAILS:
        decimal = escape_dialect(ext)
        for t, of in whole.items():
            if out[at[t]][3] == WHOLE and not t.startswith('{') \
                    and all(_tailed(text, lits, s, t, out[at[t]][1], cribs, decimal) for s in of):
                out[at[t]] = out[at[t]][:3] + (PIECE,)
                if cont is not None:
                    cont.add(t)
    if HEAD_PIECES:
        # Day 27 (script residuals): a head read whole whose rest is another value of its dict or of a related name
        decimal = escape_dialect(ext)
        for t, of in whole.items():
            if out[at[t]][3] == WHOLE and not t.startswith('{') \
                    and all(_head_piece(text, lits, s, t, out[at[t]][1], cribs, decimal) for s in of):
                out[at[t]] = out[at[t]][:3] + (PIECE,)
                if cont is not None:
                    cont.add(t)
        if cont is not None:
            # A plan graded PIECE for another reason (code glued to its literal: `MATERIAL_x + suffix_x()`) whose rest
            # stands in one of those places too: listed, so that no codec label takes that literal whole (by_label).
            for t, how, _tr, grade in out:
                if grade == PIECE and t not in cont and not t.startswith('{') \
                        and any(_head_piece(text, lits, s, t, how, cribs, decimal) for s in src_of.get(t, ())):
                    cont.add(t)
    return out


# Day 9 preparation (2026-10-08, tests/test_script_b.py). A shorter literal behind the material that reads as
# its last piece: `["<piece>", "<rest>"]`, `("<piece>", "<rest>")`, `f("<piece>", "<rest>")`,
# `"%s%s" % (a, "<rest>")`, `"{}{}".format(a, "<rest>")`, `a[:] + "<rest>"`, `parts.append("<rest>")`,
# `buf.write("<rest>")`. The rules above want a neighbour of the material's own size (a chunk among chunks),
# and a rest of twelve characters is none: the piece was read as the whole material and its plan's last
# value, cut, answered plain. What is asked here needs no syntax: a literal that stands behind the material,
# in its alphabet, whose join with it decodes the same way to the same plan going on. A codec name, a key or
# a separator behind the material is no such literal, because the join then decodes to no plan at all (or to
# the same one: base64 padding). The plan is then graded PIECE (reading() leaves its last field out).
#
# The rest must be written as the material is: base64 text of four characters or more, whole hex pairs,
# numbers with the material's own separator, numeric escapes. A plain word behind a material of escapes
# (`"|"`, `"1"`, `'left'`) adds one byte each, which any transform turns into a printable character one time
# in three: 24 of the 2,874 saved specimens of Days 1 to 8 were demoted by that before the rule was this
# strict, and none is now (tests/test_script_b.py counts them when the saved attempts are there).
TAILS = True
TAIL_TRIES = 48      # literals behind the material that are tried as its rest
_ESCAPES_ONLY = re.compile(r'(?:\\(?:x[0-9A-Fa-f]{1,2};?|u00[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,4}\}|[0-9]{1,3}))+')


def _tail_shape(how: str, s: str):
    """The pattern a literal must match in full to be more of a material that decoded as `how`, or None when
    this rule has no opinion on that representation."""
    if '\\' in s:
        return _ESCAPES_ONLY
    if how.startswith('base64'):
        return re.compile(r'[A-Za-z0-9+/_-]{4,}={0,2}|[A-Za-z0-9+/_-]{2,3}={1,2}')
    if how in ('hex_compact', 'percent_hex'):
        return re.compile(r'(?:%?[0-9A-Fa-f]{2})+')
    m = re.fullmatch(r'(hex|decimal|hex_frag)_(.)', how, re.S)
    if m:
        d = re.escape(m.group(2))
        return re.compile(r'%s?[0-9A-Fa-f]{1,3}(?:%s[0-9A-Fa-f]{1,3})*' % (d, d))
    return None


def _tailed(text, lits, s, plan, how, cribs, decimal) -> bool:
    """Whether a literal behind the literal `s` reads as more of it: s + literal decodes as `how` to a plan
    that begins with `plan` and goes on (see above). False for a source that is no string."""
    if not isinstance(s, str) or not s:
        return False
    alphabet = _tail_shape(how or '', s)
    if alphabet is None:
        return False
    first = next((b for _, b, v, _ in lits if v == s), None)
    if first is None:
        first = text.find(s)
        if first < 0:
            return False
        first += len(s)
    tried = set()

    def emit(h, data):
        yield h, data

    own = _line_start(text, first - len(s) - 1)
    names = set(re.findall(r'[A-Za-z_]\w*', text[own:max(own, first - len(s) - 1)])) - _KEYWORDS - _DECL_NAMES
    if names:
        # A name the material is passed on to (`parts = [MATERIAL]`) is a name of it too: two rounds over the
        # assignments behind it, in at most TAIL_SCAN characters.
        behind = text[first:first + TAIL_SCAN]
        for _ in range(2):
            for m in _TAIL_ASSIGN.finditer(behind):
                if m.group(1) not in names and names & set(re.findall(r'[A-Za-z_]\w*', m.group(2))):
                    names.add(m.group(1))
    for a, b, v, _ in lits:
        if a < first or not v or len(v) >= len(s) or v in tried or not alphabet.fullmatch(v):
            continue
        if not _tail_place(text, first, a, b, names):
            continue
        tried.add(v)
        if len(tried) > TAIL_TRIES:
            break
        for h, data in string_forms(s + v, emit, decimal):
            if h != how:
                continue
            data = list(data)
            if not all(0 <= x < 256 for x in data):
                continue
            for _, raw in undo(data, cribs):
                t = looks_like_plan(raw)
                if t and len(t) > len(plan) and t.startswith(plan) and _TAIL_TEXT.fullmatch(t, len(plan)):
                    return True
    return False


# Where a rest stands, and what it reads as. Re-encoding every saved specimen's plan as base64 and hex under
# four keys (4,788 cases) showed 39 literals that pass the decode alone: `'left'`, `"cfg="`, `'url'`,
# `'__import__'` behind a base64 material decode to two or three printable characters (`R *`, `G%`, `}~`).
# So both of these are asked as well:
#   the place   right behind the material in one bracket or statement (at most TAIL_GAP characters between
#               them, no `;`, one line end at most): the next item of a list, a tuple, a call or a dict;
#               or, on a line that names a word of the material's own line before it (its variable, the
#               object it is written to), an argument of a call that adds text (append, extend, write,
#               format, .., `%`) or the operand of a join (`+ "<rest>"`, `. "<rest>"`, `& "<rest>"`, `<<`);
#   the text    what the join adds to the plan is plan text: letters, digits and `_ . : / \ | = , @ + -`.
TAIL_GAP = 24
_TAIL_TEXT = re.compile(r'[A-Za-z0-9_.:/\\|=,@+-]+')
_TAIL_ADDS = re.compile(r'(?:\b(?:append|extend|add|push|push_str|concat|Concat|Append|write|Write|insert|format|'
                        r'Format|join|Join|printf|sprintf|paste0?|str_c|strcat)[ \t]*\(|%[ \t]*\(|<<|\+=|\.=|&=|\.\.=)'
                        r'[ \t]*[\[({]?[ \t]*(?:[\w$@.\[\]:]{1,40}[ \t]*,[ \t]*){0,3}[bBrRuU]{0,2}$')
_TAIL_JOINS = re.compile(r'(?:\+|&|\.\.?|<>|<<)[ \t]*[bBrRuU]{0,2}$')


_DECL_NAMES = {"local", "my", "our", "var", "let", "const", "def", "Local", "Global", "Dim", "Const", "readonly",
               "static", "final", "String", "string", "val", "mutable", "auto", "set", "php"}


TAIL_SCAN = 1 << 16
_TAIL_ASSIGN = re.compile(r'(?m)^[ \t]*' + _DECL_WORDS + r'\$?([A-Za-z_]\w*)[ \t]*(?::?=|<-)[ \t]*([^\r\n]{1,200})')
# What may stand between the material and a rest that is the next item beside it: brackets, commas, a short
# key (`'b': `, `b: `, `b => `), or the next line's own assignment to a name (one variable per chunk).
_TAIL_BESIDE = re.compile(r'''(?:[\s,\[\](){}]|'[^'\r\n]{0,12}'[ \t]*(?::|=>)|"[^"\r\n]{0,12}"[ \t]*(?::|=>)'''
                          r'''|\$?[A-Za-z_]\w{0,15}[ \t]*(?::|=>?|<-))*[bBrRuU]{0,2}''')


def _tail_place(text, end, a, b, names=()) -> bool:
    """Whether the literal text[a:b] stands where a rest of the material that ends at `end` would (see above).
    `names` are the words of the material's own line before it."""
    gap = text[end:a]
    if len(gap) <= TAIL_GAP and gap.count('\n') <= 1 and _TAIL_BESIDE.fullmatch(gap):
        return True
    line = _line_start(text, a)
    if not (_TAIL_ADDS.search(text, max(line, a - 120), a) or _TAIL_JOINS.search(text, max(line, a - 8), a)):
        return False
    stop = text.find('\n', b)
    words = set(re.findall(r'[A-Za-z_]\w*', text[line:stop if stop >= 0 else len(text)]))
    return bool(words & set(names))


# Day 27 (script residuals; left open by the review of the script-variants track): a HEAD PIECE read whole through
# a dict or a suffix variable. The material cut in two, a long head and a short rest, with the rest
#   in a dict             {"material_head_x": "<head>", "material_tail_x": "<rest>"} (a key longer than the 12
#                         characters _TAIL_BESIDE reads), other entries between the two ("mode": "inert", "count":
#                         3), a nested dict ({"a": {"x": "<head>"}, "b": {"y": "<rest>"}}), the rest's entry first;
#   in a suffix variable  MATERIAL_x = "<head>" and MATERIAL_x_SUFFIX = "<rest>" (a name longer than the 16
#                         characters _TAIL_BESIDE reads, not on the next line, joined where no text rule sees it).
# The rule of like literals wants a neighbour of half the head's size, and TAILS a rest in one of _tail_place's
# places, so the head was graded WHOLE: reading() took its plan whole (generic's cut False), its cut last value went
# out PLAIN (`file_path=C:/Progr`, `next_stage=st`), and day23_fold's -indicator claimed every key behind the cut
# absent. Now a WHOLE plan read from a literal that is the value of a dict entry (also a keyed write: `d["k"] = `,
# `d.Add "k", `), or that is assigned to a name that another assignment's name extends (NAME and NAME<more>) or
# shares a stem with (part_head, part_tail), is a PIECE when a value of the same dict (the outermost bracket that
# holds the entry; the other keyed writes to the same container), of such a name, or a function's `return "<v>"`
#   decodes on from it   the head with it (behind or before it, a partial last group of it left out) decodes as the
#                        head did to a longer plan that begins with the head's and goes on in plan text (_TAIL_TEXT);
#   or is long           HEAD_LONG characters or more of the head's own representation (_tail_shape), as the value
#                        of a dict entry or of a NAME<more> variable: a piece encoded on its own, or a middle piece,
#                        need not decode on from the head, and nothing then proves the head whole.
# Only a plan read whole is touched, and only to PIECE: reading() then leaves its last field out, as for any piece.
# A plan already a PIECE for another reason (code glued to it) whose rest stands in such a place is listed too
# (continued_plans), so that no codec label (generic.by_label), shapes_py or lang_sh takes that literal whole.
# A dict whose other values are short words that decode to nothing (`codec: "base64"`) leaves its value whole.
# On every saved Script member (4,263 distinct texts) the rule changes no reading.
HEAD_PIECES = True
HEAD_SCAN = 1 << 12        # characters before a dict value searched for the brackets that hold it
HEAD_SPAN = 1 << 16        # characters of one dict read for its other values
HEAD_TRIES = 48            # values decoded as the rest of one head
HEAD_LONG = 16             # a value of the head's representation this long is a piece of it with no decode
HEAD_LEVELS = 8            # dicts climbed out of (a dict that is an entry's value or a list's item)
_HEAD_KEY = r'(?:"[^"\r\n]{0,80}"|\'[^\'\r\n]{0,80}\'|[A-Za-z_$@][\w$.-]{0,80}|\[[^\[\]\r\n]{1,80}\])'
# The value of a dict entry: `key: "<v>"`, `"key" => "<v>"`, and `key = "<v>"` behind a bracket, a comma or a `;` on
# its line (`{a = "<v>", ..}`, `dict(a="<v>")`, `@{ A = '<v>'; .. }`), or on a line of its own that a comma ends (a
# Lua table over several lines). A plain assignment (`NAME = "<v>"` that begins its line) is no entry.
_ENTRY_COLON = re.compile(_HEAD_KEY + r'[ \t]*(?::|=>)[ \t]*[@bBrRuU]{0,2}$')
_ENTRY_EQ = re.compile(r'[{(\[,;][ \t]*' + _HEAD_KEY + r'[ \t]*=[ \t]*[@bBrRuU]{0,2}$')
_ENTRY_EQ_LINE = re.compile(r'[ \t]*' + _HEAD_KEY + r'[ \t]*=[ \t]*[@bBrRuU]{0,2}$')
_ITEM_BEFORE = re.compile(r'(?:[\[(,]|(?::?=|<-|=>|:))[ \t]*[@]?[ \t]*$')
_KEY_AFTER = re.compile(r'[ \t]*(?::(?!:)|=>|=(?!=))')
_BLOCK_BEFORE = re.compile(r'(?:\)|\belse|\bdo|\btry|\bfinally|=>|->)[ \t\r\n]*$')
_BRACKET_RE = re.compile(r'[()\[\]{}]')
_ASSIGN_HEAD = re.compile(r'[ \t]*' + _DECL_WORDS + r'\$?([A-Za-z_]\w*)' + _TYPED + r'[ \t]*(?::?=|<-)[ \t]*[bBrRuU]{0,2}$')


def _in_lit(starts, ends, i) -> bool:
    k = bisect.bisect_right(starts, i) - 1
    return k >= 0 and i < ends[k]


def _open_before(text, starts, ends, at, stop) -> int:
    """The innermost bracket left open before `at` (string literals stepped over), searched back to `stop`; -1."""
    depth = 0
    for i in reversed([m.start() for m in _BRACKET_RE.finditer(text, stop, at)]):
        if _in_lit(starts, ends, i):
            continue
        if text[i] in ')]}':
            depth += 1
        elif depth:
            depth -= 1
        else:
            return i
    return -1


def _close_after(text, starts, ends, o) -> int:
    """The bracket that closes the one opened at `o`, within HEAD_SPAN characters (string literals stepped over); -1."""
    depth = 0
    for m in _BRACKET_RE.finditer(text, o, min(len(text), o + HEAD_SPAN)):
        i = m.start()
        if _in_lit(starts, ends, i):
            continue
        if text[i] in '([{':
            depth += 1
        else:
            depth -= 1
            if not depth:
                return i
    return -1


def _entry_value(text, a, b):
    """'colon', 'eq' or None: whether the literal text[a:b] is the value of a dict entry (see above), and how."""
    line = _line_start(text, a)
    head = text[max(line, a - 200):a]
    if _ENTRY_COLON.search(head):
        return 'colon'
    if _ENTRY_EQ.search(head) or (_ENTRY_EQ_LINE.fullmatch(text, line, a) and re.match(r'[ \t]*,', text[b:b + 8])):
        return 'eq'
    return None


def _dict_values(text, lits, starts, ends, a, b):
    """[(value, is_entry)]: the other literals of the outermost dict that holds the entry whose value is text[a:b]
    (keys left out), or [] when it is no entry of a dict."""
    kind = _entry_value(text, a, b)
    if kind is None:
        return []
    o = _open_before(text, starts, ends, a, max(0, a - HEAD_SCAN))
    if o < 0 or (kind == 'eq' and text[o] == '{' and text[o - 1:o] != '@'
                 and _BLOCK_BEFORE.search(text, max(0, o - 16), o)):
        return []                                  # no bracket holds it, or a `key = ` in a block of code
    for _ in range(HEAD_LEVELS):
        line = _line_start(text, o)
        before = text[max(line, o - 200):o]
        if not (_ENTRY_COLON.search(before) or _ENTRY_EQ.search(before) or _ITEM_BEFORE.search(before)) \
                or _BLOCK_BEFORE.search(text, max(0, o - 16), o):
            break
        up = _open_before(text, starts, ends, o, max(0, o - HEAD_SCAN))
        if up < 0 or (text[up] == '{' and text[up - 1:up] != '@' and _BLOCK_BEFORE.search(text, max(0, up - 16), up)):
            break
        o = up                                     # a dict that is an entry's value or a list's item: the one around it
    c = _close_after(text, starts, ends, o)
    if c < 0:
        return []
    lo, hi = bisect.bisect_right(starts, o), bisect.bisect_left(starts, c)
    out = []
    for x, y, v, _ in lits[lo:hi]:
        if x == a or _KEY_AFTER.match(text, y):
            continue
        out.append((v, _entry_value(text, x, y) is not None))
    return out


def _stem(name: str) -> str:
    """A name without its last `_word` (`MATERIAL_c0ffee12` -> `MATERIAL_`) or its trailing digits (`part1` ->
    `part`), when three characters or more are left; else the name."""
    if '_' in name[1:-1]:
        cut = name[:name.rindex('_') + 1]
    else:
        cut = name.rstrip('0123456789')
    return cut if len(cut) >= 3 else name


def _suffix_values(text, lits, starts, a):
    """[(value, extends)]: the literals assigned to a name related to the one the literal at `a` is assigned to
    (NAME<more> or NAME's head, `extends`; or a name of NAME's stem), or [] when it is assigned to no name."""
    line = _line_start(text, a)
    m = _ASSIGN_HEAD.fullmatch(text, line, a)
    if not m:
        return []
    name = m.group(1)
    stem = min(name, _stem(name), key=len)
    pat = re.compile(r'(?m)^[ \t]*' + _DECL_WORDS + r'\$?(' + re.escape(stem) + r'\w*)' + _TYPED
                     + r'[ \t]*(?::?=|<-)[ \t]*[bBrRuU]{0,2}(?=["\'])')
    out = []
    for n in pat.finditer(text):
        other = n.group(1)
        if other == name or n.end() == a:
            continue
        k = bisect.bisect_left(starts, n.end())
        if k < len(lits) and starts[k] == n.end():
            out.append((lits[k][2], other.startswith(name) or name.startswith(other)))
        if len(out) > HEAD_TRIES:
            break
    return out


# A keyed write to a container NAME, the dict built one entry a statement: `NAME["k"] = "<v>"`, `NAME.k = "<v>"`,
# VBScript's `NAME("k") = "<v>"` and `NAME.Add "k", "<v>"`, `NAME.set("k", "<v>")`, `$NAME.Add('k', '<v>')`.
_KEYED_KEY = r'(?:"[^"\r\n]{0,80}"|\'[^\'\r\n]{0,80}\'|[A-Za-z_]\w*|\d+)'
_KEYED_FORMS = (r'(?:\[[^\[\]\r\n]{1,80}\]|\.[A-Za-z_]\w*|\([ \t]*(?:"[^"\r\n]{1,80}"|\'[^\'\r\n]{1,80}\')[ \t]*\))'
                r'[ \t]*:?=[ \t]*[@bBrRuU]{0,2}',
                r'\.(?:Add|add|set|Set|put|Put|setdefault|Item|store|Store)[ \t]*\(?[ \t]*' + _KEYED_KEY
                + r'[ \t]*,[ \t]*[@bBrRuU]{0,2}')
_KEYED_HEAD = re.compile(r'[ \t]*(?:[Ss]et[ \t]+|let[ \t]+)?\$?([A-Za-z_]\w*)(?:' + '|'.join(_KEYED_FORMS) + r')$')


def _keyed_values(text, lits, starts, a):
    """[(value, True)]: the literals of the other keyed writes to the container the literal at `a` is written into
    (`NAME["k"] = `, `NAME.Add "k", `, ..), or [] when it is no keyed write."""
    line = _line_start(text, a)
    m = _KEYED_HEAD.fullmatch(text, line, a)
    if not m:
        return []
    name = re.escape(m.group(1))
    pat = re.compile(r'(?m)^[ \t]*(?:[Ss]et[ \t]+|let[ \t]+)?\$?' + name + r'(?:' + '|'.join(_KEYED_FORMS)
                     + r')(?=["\'])')
    out = []
    for n in pat.finditer(text):
        if n.end() == a:
            continue
        k = bisect.bisect_left(starts, n.end())
        if k < len(lits) and starts[k] == n.end():
            out.append((lits[k][2], True))
            if len(out) > HEAD_TRIES:
                break
    return out


_RETURNED = re.compile(r'(?<![\w$.])return[ \t]+[bBrRuU]{0,2}(?=["\'])')


def _returned_values(text, lits, starts):
    """[(value, False)]: the literals a function returns (`return "<rest>"`, a suffix from a function), anywhere in
    the file; they count only when they decode on from the head."""
    out = []
    if 'return' not in text:
        return out
    for n in _RETURNED.finditer(text):
        k = bisect.bisect_left(starts, n.end())
        if k < len(lits) and starts[k] == n.end():
            out.append((lits[k][2], False))
            if len(out) > HEAD_TRIES:
                break
    return out


def _decodes_on(s, v, plan, how, cribs, decimal, shape) -> bool:
    """Whether the literal `v`, behind the head `s` or before it (a partial last group of it left out), decodes as
    `how` with it to a longer plan that begins with `plan` and goes on in plan text."""
    def emit(h, data):
        yield h, data
    g = 4 if how.startswith('base64') else 2 if how in ('hex_compact', 'percent_hex') else 0
    tries = [v] + ([v[:len(v) - len(v) % g]] if g and len(v) > g and len(v) % g else [])
    for x in tries:
        if not shape.fullmatch(x):
            continue
        for joined in (s + x, x + s):
            for h, data in string_forms(joined, emit, decimal):
                if h != how:
                    continue
                data = list(data)
                if not all(0 <= y < 256 for y in data):
                    continue
                for _, raw in undo(data, cribs):
                    t = looks_like_plan(raw)
                    if t and len(t) > len(plan) and t.startswith(plan) and _TAIL_TEXT.fullmatch(t, len(plan)):
                        return True
    return False


def _head_piece(text, lits, s, plan, how, cribs, decimal) -> bool:
    """Whether the literal `s`, which decodes whole as `how` to `plan`, is the head of a material whose rest is the
    value of another entry of its dict or of a related name (see above). False for a source that is no string."""
    if not isinstance(s, str) or not s:
        return False
    shape = _tail_shape(how or '', s)
    if shape is None:
        return False
    starts, ends = [x for x, _, _, _ in lits], [y for _, y, _, _ in lits]
    tried = 0
    returned = None
    for a, b, v, _ in lits:
        if v != s:
            continue
        if returned is None:
            returned = _returned_values(text, lits, starts)
        for rest, long_ok in (_dict_values(text, lits, starts, ends, a, b) + _keyed_values(text, lits, starts, a)
                              + _suffix_values(text, lits, starts, a) + returned):
            if not rest or rest == s:
                continue
            long_rest = long_ok and len(rest) >= HEAD_LONG
            if long_rest and shape.fullmatch(rest) and not (HEAD_LONG_UNRELATED and _unrelated_sibling(rest, decimal)):
                return True
            tried += 1
            if tried > HEAD_TRIES:
                return False
            if _decodes_on(s, rest, plan, how, cribs, decimal, shape):
                return True
            if HEAD_APART_TEXT and long_rest and not shape.fullmatch(rest) and _apart_text(rest, decimal):
                return True                        # a rest encoded apart, in another alphabet than the head's
    return False


# Row 563 (Day 27, after the script-residuals review, cases A1-A3; reworked after the review of rows-542-563's first
# build, which related a long sibling to the head by plan-text tests and so let 385 cut plans out whole: a cut value
# with a space, `?`, `&`, `%` or `~`, and rests encoded apart reversed, xor-ed, rot13-ed, gzip-ed or as UTF-16).
# The floor's rule stands: a long (HEAD_LONG+) value of the head's alphabet beside it makes the head a PIECE. With
# HEAD_LONG_UNRELATED on (it is OFF, below) it would be dropped ONLY for a sibling that is PROVABLY unrelated (_unrelated_sibling): a digest-like length (hex 32/40/64;
# base64 of 16/20/32 bytes, padded or not) AND, in every reading we know (as written, reversed, rot13; every
# representation string_forms and _direct read, the bytes forward and reversed), bytes that are no text under ANY
# single-byte xor key, no UTF-16 text, and no compressed stream. A sha256, a sha1, a random token beside a WHOLE
# material then leaves it whole (af3dbf7's answer); anything else is withdrawn as before. A sibling that is cut plan
# text decodes on from the head (_decodes_on, tried next for it as for every value) or reads as text alone.
# Second (withdrawal only): a long value in ANOTHER alphabet than the head's that, decoded alone in some reading,
# is text (_apart_text: a hex head beside the base64 of its rest) makes the head a piece too; the floor matched no
# hex shape there and let the cut last value out plain.
# HEAD_LONG_UNRELATED is OFF (the floor's rule exactly): the independent review of this rework found 622 new wrong
# plains from the digest-length skip (rests encoded apart by add-k, by rotation and by a short repeating xor key read
# as no text under any single-byte key), so A1-A3 stay None. Only the _apart_text withdrawal ships (HEAD_APART_TEXT;
# it only restricts plain). With HEAD_LONG_UNRELATED False, _unrelated_sibling is never called.
HEAD_LONG_UNRELATED = False
HEAD_APART_TEXT = True
_DIGEST_HEX = re.compile(r'[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}')
_DIGEST_B64 = re.compile(r'[A-Za-z0-9+/]{21}[AQgw](?:==)?|[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]=?'
                         r'|[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=?|[A-Za-z0-9_-]{21}[AQgw]|[A-Za-z0-9_-]{26}[AEIMQUYcgkosw048]'
                         r'|[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]')
_ENC_ALPHABET = re.compile(r'={0,2}[A-Za-z0-9+/_-]+={0,2}')
_PRINTABLE = frozenset(range(0x20, 0x7f)) | {9, 10, 13}
_ROT13 = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                       'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')


def _readings(rest, decimal):
    """Every byte string the literal `rest` decodes to, alone, in a reading we know."""
    out = []
    for t in dict.fromkeys((rest, rest[::-1], rest.translate(_ROT13), rest[::-1].translate(_ROT13))):
        if re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', t):
            out.append(bytes.fromhex(t))
        if _ENC_ALPHABET.fullmatch(t) and len(t.rstrip('=')) % 4 != 1:
            u = t.rstrip('=').translate(URLSAFE)
            try:
                out.append(base64.b64decode(u + '=' * (-len(u) % 4), validate=True))
            except Exception:  # noqa: BLE001 - no base64 after all
                pass
        try:
            for _, data in list(string_forms(t, _raw, decimal)) + list(_direct(t)):
                data = list(data)
                if data and all(0 <= y < 256 for y in data):
                    out.append(bytes(data))
        except Exception:  # noqa: BLE001 - a reading that breaks is no reading
            pass
    return out


def _texty(b, again=True) -> bool:
    """Whether the bytes `b` are (or may be) text: printable under some single-byte xor key, UTF-16 text under one,
    or a compressed stream (one with a header; a headerless deflate stream when what it gives is such text). Errs
    toward True: True only withdraws."""
    if len(b) < 4:
        return True
    if b[:2] == b'\x1f\x8b' or b[:3] == b'BZh' or b[:6] == b'\xfd7zXZ\x00' or _inflated(b):
        return True
    if again:
        try:
            o = zlib.decompressobj(-15)
            out = o.decompress(b, MAX_INFLATE)
            if out and o.eof and _texty(out, False):
                return True
        except zlib.error:
            pass
    seen = set(b)
    if any(all((x ^ k) in _PRINTABLE for x in seen) for k in range(256)):
        return True
    for even, odd in ((b[0::2], b[1::2]), (b[1::2], b[0::2])):
        if len(set(odd)) == 1:
            k = odd[0]
            if all((x ^ k) in _PRINTABLE for x in even):
                return True
    return False


def _unrelated_sibling(rest, decimal) -> bool:
    """Whether a long sibling of the head's alphabet is PROVABLY no piece of its material (see above)."""
    if not (_DIGEST_HEX.fullmatch(rest) or _DIGEST_B64.fullmatch(rest)):
        return False
    reads = _readings(rest, decimal)
    return bool(reads) and not any(_texty(b) for b in reads)


def _apart_text(rest, decimal) -> bool:
    """Whether a long value of an encoding alphabet reads, decoded alone, as text in some reading (see above)."""
    if not _ENC_ALPHABET.fullmatch(rest):
        return False
    return any(len(b) >= 8 and _texty(b) for b in _readings(rest, decimal))


def plans(text: str, ext=None) -> list:
    """graded_plans() without the grade: [(plan text, representation, transform)]. recover
    returns the first of these."""
    return [p[:3] for p in graded_plans(text, ext)]


def _conflict(a: dict, b: dict):
    """The first key two flat plans both hold with different values, or None."""
    return next((k for k in a if k in b and str(a[k]) != str(b[k])), None)


# Perf (2026-10-24): within one analyze.solve_set call both the main solve path (generic.answers ->
# generic.read) and day23_fold.patch (_plan_of -> generic.read) call reading() with the SAME (text, ext)
# for the same specimen bytes, so reading() -- the dominant cost of a Day 18 Mastery solve -- ran twice per
# specimen (655 _plan_of reads, ~2 s of a ~5.7 s profiled run). reading() is a pure function of (text, ext)
# returning an immutable (got, note), so analyze.solve_set memoizes it for the call's duration (the second
# call is then a cache hit). No answer changes: the cache hits only on an identical (ext, text), and what it
# returns is byte-for-byte what a fresh call would. The counter lets the nested solve_set calls day23_fold
# makes share the outer cache and tears it down only when the outermost solve_set exits (so memory is bounded
# to one delivery). Off everywhere but analyze.solve_set (every other path runs _reading_impl exactly).
_READING_MISS = object()
_READING_CACHE = None
_READING_DEPTH = 0


def reading_cache_begin():
    global _READING_CACHE, _READING_DEPTH
    if _READING_DEPTH == 0:
        _READING_CACHE = {}
    _READING_DEPTH += 1


def reading_cache_end():
    global _READING_CACHE, _READING_DEPTH
    if _READING_DEPTH > 0:
        _READING_DEPTH -= 1
    if _READING_DEPTH == 0:
        _READING_CACHE = None


def memo_cache():
    """The reading cache's dict while analyze.solve_set runs, else None. Another pure function of this lane may
    keep its results there under a key of its own (a tuple whose first item names the function, never a 2-tuple
    (ext, text) as reading() uses), with the same lifetime: the outermost solve_set (Day 27 speed build:
    descriptor.decode)."""
    return _READING_CACHE


# Day 27 (script residuals): the plan text reading() settled on for a text, BEFORE it left the last field out (a plan
# read from a piece), by (ext, text); bounded, filled by _reading_impl. longest() hands it to the readers that read
# one literal on their own (generic.by_label's codec label, shapes_py): a plan of theirs that is only the head of the
# plan reading() saw go on is a head piece, never a whole plan.
_LONGEST = {}
LONGEST_MAX = 256


def _bounded_put(table, key, value):
    """table[key] = value, the oldest entry dropped past LONGEST_MAX (a drop that races another thread is skipped)."""
    if key not in table and len(table) >= LONGEST_MAX:
        try:
            table.pop(next(iter(table)), None)
        except (RuntimeError, StopIteration):
            pass
    table[key] = value


def _remember_longest(text, ext, plan):
    _bounded_put(_LONGEST, (ext, text), plan)


def longest(text: str, ext=None):
    """The longest plan text reading() found for `text` (the one it took, before it left a piece's last field out),
    or None when it found none or two plans."""
    key = (ext, text)
    if key not in _LONGEST:
        # Through reading()'s cache: a caller that reads the text before the general path does (lang_sh, which
        # analyze asks before generic) then costs that path nothing; a direct _reading_impl here decoded each
        # such specimen twice (Day 9's Mastery: +0.11 s).
        reading(text, ext)
        if key not in _LONGEST:          # reading() answered from its cache and this table had dropped the entry
            _reading_impl(text, ext)
    return _LONGEST.get(key)


def head_of(t, longer) -> bool:
    """Whether the plan text `t` is only the head of the plan text `longer`: `longer` begins with it and goes on, or
    holds its fields in the same order with the same values but the last, whose value begins `longer`'s value of
    that key, and `longer` goes on past it (a longer last value, or more fields)."""
    if not isinstance(t, str) or not isinstance(longer, str) or not t or t == longer:
        return False
    if longer.startswith(t):
        return True
    a, b = list(flatten(t).items()), list(flatten(longer).items())
    if not a or len(a) > len(b) or [k for k, _ in a] != [k for k, _ in b[:len(a)]]:
        return False
    if any(str(x[1]) != str(y[1]) for x, y in zip(a[:-1], b)):
        return False
    va, vb = str(a[-1][1]), str(b[len(a) - 1][1])
    return vb.startswith(va) and (len(a) < len(b) or len(vb) > len(va))


def reading(text: str, ext=None):
    """Cached shell over _reading_impl, which is pure in (text, ext); see reading_cache_begin. When the cache
    is off (every path but analyze.solve_set) this is _reading_impl exactly."""
    cache = _READING_CACHE
    if cache is None:
        return _reading_impl(text, ext)
    key = (ext, text)
    hit = cache.get(key, _READING_MISS)
    if hit is not _READING_MISS:
        return hit
    result = _reading_impl(text, ext)
    cache[key] = result
    return result


def _reading_impl(text: str, ext=None):
    """(got, note): what decode returns, and one line when the file did not give ONE whole plan.

    recover takes the first candidate that passes the grammar. That is the plan as long as the
    file decodes to one plan, which every saved specimen does. What recover cannot see is
    settled here, over all candidates:

      A cut plan.   The `k=v|` grammar has no end mark, so a piece of the material (the first
                    of two number arrays, a colon-separated token without its first pair)
                    passes it as a shorter plan with its last value cut. Of candidates that
                    are a prefix of one another, the longest is the plan.
      A piece.      When the longest plan itself was read from a piece (sources and
                    graded_plans: one of a run of like literals, a chunk among chunks of its
                    size, a line of a wrapped block, a join that goes on behind a comment, a
                    number list whose neighbour only lengthens its last value, a token cut
                    out of a longer literal), nothing says its last value is whole. The
                    fields before it are exact, so the plan is returned without its last
                    field, and the note says so.
      Two literals. Literals with only white space between them are one literal in some
                    languages and two arguments in others. Their join is the plan when it
                    begins a field that none of them holds alone. When it only lengthens the
                    last value of a plan one of them gives, that value has two readings: the
                    shorter plan is returned without its last field, with the note.
      Two plans.    When two candidates decode to plans that hold different values for the
                    same key (a decoy, an older copy), nothing here can tell which one the
                    script uses (the last value of a plan read from a piece is not counted:
                    it may be cut). That is no established fact: got is None and the note names
                    both. A racer's lang_<ext>.py or shapes_<ext>.py decides.

    A decoded JSON object without `steps` (a settings blob) is not a plan while another
    candidate has `steps`. A JSON descriptor ends where its brace closes and is never cut."""
    _remember_longest(text, ext, None)
    found, raw, fold = _graded_plans(text, ext)
    if not found:
        return None, None
    flat = {p[0]: flatten(p[0]) for p in found}
    pool = [p for p in found if "steps" in flat[p[0]]] or found
    best = pool[0]
    for p in pool[1:]:
        if len(p[0]) > len(best[0]) and p[0].startswith(best[0]):
            best = p
    if best[3] == PIECE and not best[0].startswith('{'):
        # Row 78: a fold of character calls gives the whole material where the file's own text gives only
        # its piece. A plan read whole is that piece's plan read whole only when all of this holds: it is
        # read from the folded text alone, it holds every field of the piece's plan with the same values
        # but the last, its value there begins with the piece's (cut) last value, and the string the
        # piece was read from stands inside the folded string the whole plan was read from. Anything
        # else (a decoy that differs only in its last value, in either order) is left to the conflict
        # check below.
        items = list(flat[best[0]].items())
        head, (last_key, last_value) = dict(items[:-1]), items[-1]
        piece_src = [s for s in raw.get(best[0], set()) | fold.get(best[0], set()) if s]
        whole = [p for p in pool if p[3] == WHOLE and not p[0].startswith('{')
                 and all(str(flat[p[0]].get(k)) == str(v) for k, v in head.items())]
        if len(whole) == 1:
            w = whole[0]
            if (w[0] not in raw and last_key in flat[w[0]]
                    and str(flat[w[0]][last_key]).startswith(str(last_value))
                    and any(s in f for s in piece_src for f in fold.get(w[0], ()) if f)):
                best = w
    for p in pool:
        if p[0] == best[0] or best[0].startswith(p[0]):
            continue
        theirs = flat[p[0]]
        if p[3] == PIECE and not p[0].startswith('{'):
            # A plan read from a piece has an unreliable last value (a number cut in two, an escape
            # read across the cut): that one value contradicts nothing.
            theirs = dict(list(theirs.items())[:-1])
        key = _conflict(flat[best[0]], theirs)
        if key is not None:
            # The key is specimen text: printed escaped and cut.
            return None, (f"two different plans decode ({best[1]} | {best[2]} and {p[1]} | {p[2]}; they differ on "
                          f"{ascii(str(key))[:60]}): neither is taken")
    _LONGEST[(ext, text)] = best[0]                # longest(): the plan taken, before a piece's last field goes
    plan, how, transform, grade = best
    if plan.startswith('{') or grade == WHOLE:
        return best[:3], None
    why = "it was read from a piece of the material"
    if grade == ADJACENT:
        # The longest plan a single source gives, when the join adds no field to it.
        alone = max((p for p in pool if p[3] != ADJACENT and len(p[0]) < len(plan) and plan.startswith(p[0])),
                    key=lambda p: len(p[0]), default=None)
        if alone is None or not _lengthens(alone[0], plan):
            return best[:3], None
        plan, how, transform = alone[:3]
        why = "literals with only white space between them lengthen it, and they may be one literal or two"
    kept = plan[:plan.rfind('|') + 1]
    if kept == plan:
        return (plan, how, transform), None
    # The dropped field is specimen text: its key is printed escaped and cut.
    return (kept, how, transform), (f"the last field of the plan ({ascii(plan[len(kept):].partition('=')[0])[:60]}) is left "
                                    f"out: {why} ({how} | {transform})")


def decode(text: str, ext=None):
    """(plan text, representation, transform), or None: the one plan of the file (see reading).

    One more source when nothing decodes: numbered clear-text fragments (`set frag0=...`),
    joined in order and accepted only by the same strict grammar and only when the numbering
    has no gap."""
    got, note = reading(text, ext)
    if got or note:
        return got
    frags = {}
    # [ \t]* and not \s* around the line: \s also takes line ends, and a file of blank lines is then read squared.
    for m in re.finditer(r'(?im)^[ \t]*set[ \t]+"?([A-Za-z_]\w*?)(\d+)=(.*?)"?[ \t]*(?:&[ \t]*rem\b.*)?\r?$', text):
        frags.setdefault(m.group(1).lower(), {})[int(m.group(2))] = m.group(3).replace('^|', '|')
    best = max(frags.values(), key=len, default={})
    if best and sorted(best) == list(range(min(best), min(best) + len(best))):
        joined = ''.join(best[i] for i in sorted(best))
        t = looks_like_plan(joined.encode('latin-1', 'replace'))
        if t:
            return t, 'plain_fragments', 'identity'
    return None


def plan_of(text: str, ext=None) -> dict:
    """The flat plan of a specimen, {} when none is recovered."""
    got = decode(text, ext)
    return flatten(got[0]) if got else {}


def label_of(text: str, ext=None):
    """The in-file codec label as [representation, transform, key...], or None.

    A `HUNTRESS-CODEC:` comment or a `Codec_x = "rep|transform|key"` constant, plus the
    patterns of hooks_<ext>.py (tried first; a hook's first match is taken as it is, which
    is how a racer overrides). Only text shaped like a label counts.

    The built-in patterns are read over the whole file: when they find labels that name
    different codecs (a decoy comment beside the real constant), there is no telling which
    one the script uses, so None is returned and the codec questions fall back to what the
    decode itself shows. labels_in() lists what was found."""
    for p in (hooks(ext)[1] if ext is not None else []):
        try:
            m = re.search(p, text)
        except re.error:
            continue
        if m and m.groups() and m.group(1) and LABEL_RE.fullmatch(m.group(1).strip()):
            return m.group(1).strip().split('|')
    found = labels_in(text)
    return found[0].split('|') if len({tuple(f.split('|')[:2]) for f in found}) == 1 else None


def labels_in(text: str) -> list:
    """Every distinct label the built-in patterns find in the file, in pattern order."""
    out = []
    for p in LABEL_PATTERNS:
        if p in LABEL_GUARDS and LABEL_GUARDS[p] not in text:
            continue
        for m in re.finditer(p, text):
            s = (m.group(1) or "").strip()
            if LABEL_RE.fullmatch(s) and s not in out:
                out.append(s)
    return out


def how_slug(how: str) -> str:
    """A representation as recover names it ('hex_:', 'decimal_,') in the spelling a label key
    can carry ('hex_colon', 'decimal_comma')."""
    base, sep, d = (how or "").rpartition('_')
    if sep and d in DELIMITER_NAMES:
        return f"{base}_{DELIMITER_NAMES[d]}"
    return re.sub(r"[^a-z0-9]+", "_", (how or "").lower()).strip("_")


def transform_kind(transform: str) -> str:
    """A transform as recover names it, without its key: 'reverse+xor_5a' -> 'reverse_xor'."""
    order, _, tr = (transform or "").rpartition('+')
    kind = re.sub(r'_(?:seed_)?[0-9a-f]{2,}$|_\d+$', '', tr)
    kind = "rolling_xor" if kind.startswith("rolling_xor") else kind
    return (order + "_" if order else "") + kind


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: plan_codec.py <specimen> [...]   (prints the plan and codec label each file carries)")
    for arg in sys.argv[1:]:
        try:
            raw = Path(arg).read_bytes()
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        body, suffix = text_of(raw), Path(arg).suffix
        got, why = decode(body, suffix), reading(body, suffix)[1]
        print(f"{arg}: " + (f"{got[1]} | {got[2]}\n  plan: {got[0]}" if got else f"NO PLAN RECOVERED{' (' + why + ')' if why else ''}"))
        print(f"  label: {'|'.join(label_of(body, suffix) or []) or 'none'}")
