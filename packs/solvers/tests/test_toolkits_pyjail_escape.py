"""B-051: shared pyjail gadget library + interactive escape driver.

Three surfaces are covered, each with a test that fails when the behaviour is wrong:

  * ``pyjail_gadgets`` -- the reusable object-graph vocabulary: denylist-evasion literal splitting,
    the subclass-by-name / ``__init__.__globals__`` / frame-walk builders, gadget ranking under a
    jail profile (audit hook, parsed audit policy, blocked subclasses, banned features/substrings),
    and the audit-hook parser over jail source read as data.

  * payload conformance -- the driver's probe and exploit payloads are run in a *fresh child of our
    own CPython* (``python -I``, empty ``__builtins__``, the escape classes' modules imported).  That
    is our own interpreter running strings we assembled, never a challenge binary; it proves the
    routes (including the ``Popen -> os.__dict__`` hop) work on real CPython, not just in the fake.

  * ``pyjail_interactive`` -- the escape driver, run end to end through a real
    ``live_harness.Session`` (scope-checked against the suite's loopback scope, default ``line``
    framing) to a **loopback fake REPL** the test starts on 127.0.0.1.  The fake is a safe synthetic
    jail emulator: it parses each payload line into an AST and interprets a whitelist of nodes over
    hand-built fake objects modelling the ``().__class__.__base__.__subclasses__()`` ->
    ``__init__.__globals__`` (-> ``[os].__dict__``) -> ``write``/``environ``/``open``/``read`` graph.
    It executes nothing real, so the driver genuinely has to assemble correct payloads and discover
    the live class by probing.  Hostile variants echo the input, lag one reply behind, or answer
    slowly.
"""
import ast
import binascii
import io
import json
import os
import re
import socketserver
import string
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout

import pytest

import live_harness as lh
import pyjail_gadgets as pg
import pyjail_interactive as pji


# ===========================================================================================
#  pyjail_gadgets -- library unit tests
# ===========================================================================================

def _reconstruct_str_literals(expr: str, *, region_from: str = "", region_to: str = "") -> str:
    """Parse ``expr`` and join every string Constant inside it (used to verify ban-evasion)."""
    if region_from:
        expr = expr.split(region_from, 1)[1]
    if region_to:
        expr = expr.split(region_to, 1)[0]
    tree = ast.parse("(" + expr + ")", mode="eval")
    return "".join(node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str))


def test_split_literal_joins_back_and_evades():
    parts = pg.split_literal("__builtins__", ["builtins"])
    assert "".join(parts) == "__builtins__"
    assert all("builtins" not in p for p in parts)
    # More than one banned token at once.
    parts2 = pg.split_literal("os.system", ["system", "os."])
    assert "".join(parts2) == "os.system"
    assert all("system" not in p and "os." not in p for p in parts2)


def test_split_literal_cuts_one_char_into_a_two_char_token():
    # A two-character ban leaves exactly one place to cut: right after its first character.
    assert pg.split_literal("__builtins__", ["bu"]) == ["__b", "uiltins__"]
    assert pg.split_literal("xab", ["ab"]) == ["xa", "b"]


def test_split_literal_single_char_ban_is_impossible_and_refused():
    # A one-character ban cannot be evaded by splitting; the library must fail loudly, not silently.
    with pytest.raises(pg.GadgetError):
        pg.split_literal("banana", ["a"])


def test_literal_expr_source_has_no_banned_token_but_rebuilds_value():
    expr = pg.literal_expr("environ", ["environ", "env"])
    assert "environ" not in expr and "env" not in expr
    # Independently evaluate the pure-literal concatenation back to the original value.
    rebuilt = eval(expr, {"__builtins__": {}}, {})  # noqa: S307 - only string-literal '+' from our builder
    assert rebuilt == "environ"


def test_select_class_evades_name_ban_yet_targets_the_right_class():
    expr = pg.select_class("_wrap_close", banned=["wrap"])
    assert "wrap" not in expr
    # The reconstructed __name__ comparison literal is still exactly the target class name.
    name = _reconstruct_str_literals(expr, region_from="__name__==", region_to="][0]")
    assert name == "_wrap_close"
    assert "__subclasses__" in expr


def test_read_env_and_write_matches_the_warden_shape():
    payload = pg.read_env_and_write("_wrap_close", "FLAG", fd=1)
    # The warden route: pick the class, reach its module globals, use write + environ[FLAG].
    assert "__subclasses__" in payload and "__init__.__globals__" in payload
    assert "environ" in payload and "FLAG" in payload and "write" in payload
    # Marker wrapping brackets the value on both sides for clean in-band capture.
    wrapped = pg.read_env_and_write("_wrap_close", "FLAG", fd=1, marker=b"MM")
    assert wrapped.count("b'MM'") == 2


def test_frame_walk_emits_the_selfref_grab_with_requested_depth():
    snippet = pg.frame_walk_locals(3)
    assert snippet.startswith("g=(g.gi_frame.f_back for _ in (1,));F=(*g,)[0];")
    assert snippet.count(".f_back") == 1 + 3  # one inside the genexp, three in the walk
    assert snippet.endswith(".f_locals")
    with pytest.raises(pg.GadgetError):
        pg.frame_walk_locals(-1)


# -- ranking ---------------------------------------------------------------------------------

def _rows(profile, **kw):
    return {r["name"]: r for r in pg.rank(profile, **kw)}


def test_rank_unrestricted_profile_keeps_every_gadget_usable():
    assert all(r["usable"] and not r["reasons"] for r in pg.rank(pg.JailProfile()))


def test_rank_audit_hook_blocks_audit_sensitive_routes_only():
    rows = _rows(pg.JailProfile(audit_hook=True))
    for name in ("os-system-cat", "os-open-read", "builtins-open-read", "builtins-import-os",
                 "builtins-exec"):
        assert rows[name]["audit_sensitive"] is True
        assert rows[name]["usable"] is False, name
        assert any("blocked audit event" in r for r in rows[name]["reasons"])
        assert rows[name]["score"] == pg._BY_NAME[name].base_rank - 25
    # The warden route raises no audit event and survives the hook; so do subclasses/__globals__.
    for name in ("environ-write", "init-globals", "subclass-by-name", "frame-walk-locals"):
        assert rows[name]["usable"] is True, name
    # gi_frame raises object.__getattr__, which a hook does not conventionally block.
    assert rows["frame-selfref"]["audit_events"] == ["object.__getattr__"]
    assert rows["frame-selfref"]["usable"] is True


def test_rank_substring_ban_is_a_penalty_that_reorders_but_does_not_block():
    clean = _rows(pg.JailProfile())
    rows = pg.rank(pg.JailProfile(banned_substrings=("subclasses",)))
    by = {r["name"]: r for r in rows}
    hit = by["subclasses-enum"]
    assert hit["usable"] is True
    assert any("banned substrings" in r and "'subclasses'" in r for r in hit["reasons"])
    assert hit["score"] == clean["subclasses-enum"]["score"] - 8
    assert by["subclass-by-name"]["score"] == clean["subclass-by-name"]["score"] - 8
    assert by["init-globals"]["reasons"] == []   # no 'subclasses' in its template
    # Unpenalised it leads (70); penalised (62) it drops below init-globals (66) and environ-write (64).
    assert [r["name"] for r in pg.rank(pg.JailProfile())][0] == "subclasses-enum"
    assert [r["name"] for r in rows][:3] == ["init-globals", "environ-write", "subclasses-enum"]


def test_rank_sorts_every_usable_row_before_any_blocked_row():
    rows = pg.rank(pg.JailProfile(banned_features=frozenset({"comprehension"})))
    usable = [r for r in rows if r["usable"]]
    blocked = [r for r in rows if not r["usable"]]
    # Precondition that makes the order meaningful: a blocked row outscores a usable one.
    assert blocked and max(r["score"] for r in blocked) > min(r["score"] for r in usable)
    assert rows == usable + blocked
    assert [r["score"] for r in usable] == sorted((r["score"] for r in usable), reverse=True)


def test_rank_blocks_subclasses_route_and_keeps_frame_route():
    rows = _rows(pg.JailProfile(subclasses_blocked=True))
    assert rows["subclass-by-name"]["usable"] is False
    assert rows["subclasses-enum"]["usable"] is False
    assert rows["catch-warnings-builtins"]["usable"] is False
    assert rows["frame-walk-locals"]["usable"] is True
    assert rows["frame-selfref"]["usable"] is True
    assert rows["init-globals"]["usable"] is True        # reachable via func-globals, no enumeration
    usable = pg.rank(pg.JailProfile(subclasses_blocked=True), include_blocked=False)
    assert all("__subclasses__" not in row["template"] for row in usable)


def test_rank_banned_feature_blocks_comprehension_gadgets():
    rows = _rows(pg.JailProfile(banned_features=frozenset({"comprehension"})))
    assert rows["subclass-by-name"]["usable"] is False   # needs a comprehension
    assert rows["init-globals"]["usable"] is True        # pure attribute access


def test_rank_dunder_ban_keeps_the_frame_route_and_blocks_the_subclass_route():
    # The 9124 frame walk uses gi_frame/f_back/f_locals: plain attributes, no dunder.  Under a dunder
    # ban it is the route to take, so it must stay usable.
    rows = _rows(pg.JailProfile(banned_features=frozenset({"dunder"})))
    assert rows["frame-selfref"]["usable"] is True and rows["frame-selfref"]["reasons"] == []
    assert rows["frame-walk-locals"]["usable"] is True and rows["frame-walk-locals"]["reasons"] == []
    for name in ("subclass-by-name", "subclasses-enum", "init-globals", "catch-warnings-builtins"):
        assert rows[name]["usable"] is False
        assert rows[name]["reasons"] == ["uses banned features: dunder"]


_EXPR_FIELDS = {"class_expr", "func_expr", "globals_expr", "builtins_expr", "frame_expr"}


def _fill_template(template: str) -> str:
    """Fill a gadget template with neutral stand-ins: names for expressions, 's' for literals."""
    values = {}
    for _, field, _, _ in string.Formatter().parse(template):
        if not field:
            continue
        values[field] = ("E" if field in _EXPR_FIELDS else "v" if field == "var"
                         else "i" if field == "inner" else ".f_back" if field == "backs" else "'s'")
    return template.format(**values)


def _features_of(src: str) -> set[str]:
    """The FEATURES a piece of source really uses, read off its AST."""
    found = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Attribute):
            found.add("attribute")
            if node.attr.startswith("__") and node.attr.endswith("__"):
                found.add("dunder")
        elif isinstance(node, ast.Subscript):
            found.add("subscript")
        elif isinstance(node, ast.Call):
            found.add("call")
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            found.add("comprehension")
        elif isinstance(node, (ast.NamedExpr, ast.Assign)):
            found.add("assignment")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.add("string")
    return found


def test_every_gadget_declares_exactly_the_features_its_template_uses():
    # rank() filters on the declared features, so a wrong declaration blocks a usable route (or
    # passes a blocked one).  Derive the truth from each template's AST.
    for gadget in pg.GADGETS:
        assert set(gadget.uses) == _features_of(_fill_template(gadget.template)), gadget.name
    assert _features_of(pg.frame_walk_locals(3)) == {"attribute", "assignment", "comprehension",
                                                     "subscript"}


def test_rank_rejects_unknown_feature():
    with pytest.raises(pg.GadgetError):
        pg.rank(pg.JailProfile(banned_features=frozenset({"telepathy"})))


# -- audit-hook parser -----------------------------------------------------------------------

DENY_HOOK = '''
import sys
BAD = {"os.system", "open"}
def hook(event, args):
    if event in BAD:
        raise RuntimeError("blocked")
    if event.startswith("subprocess."):
        raise RuntimeError("blocked")
sys.addaudithook(hook)
'''

ALLOW_HOOK = '''
import sys
OK = frozenset(["compile", "exec", "object.__getattr__"])
def warden(ev, a):
    if ev not in OK:
        raise PermissionError(ev)
sys.addaudithook(warden)
'''

EARLY_RETURN_HOOK = '''
from sys import addaudithook
def h(ev, a):
    if ev == "exec" or ev == "compile":
        return
    raise SystemExit
addaudithook(h)
'''

LAMBDA_HOOK = '''
import sys, os
sys.addaudithook(lambda e, a: os._exit(1) if e in ("open", "import") else None)
'''

OPAQUE_HOOK = '''
import sys
def h(ev, a):
    if len(a) > 2:
        raise RuntimeError
sys.addaudithook(h)
'''


NARROWED_HOOK = '''
import sys
def h(ev, a):
    if ev not in ("open", "os.system"):
        return
    raise RuntimeError(ev)
sys.addaudithook(h)
'''

CONTAINS_HOOK = '''
import sys
def h(event, args):
    if "socket" in event or "ctypes" in event:
        raise RuntimeError(event)
sys.addaudithook(h)
'''


def _verdicts(policy, events=("open", "os.system", "subprocess.Popen", "exec", "compile",
                              "object.__getattr__", "import")):
    return {e: policy.blocks(e) for e in events}


def test_parse_denylist_hook_with_named_set_and_prefix():
    policy = pg.parse_audit_hooks(DENY_HOOK)
    assert policy.hooks == ("hook",)
    assert policy.allow is None
    assert _verdicts(policy) == {"open": True, "os.system": True, "subprocess.Popen": True,
                                 "exec": False, "compile": False, "object.__getattr__": False,
                                 "import": False}


def test_parse_allowlist_hook_blocks_everything_not_listed():
    policy = pg.parse_audit_hooks(ALLOW_HOOK)
    assert policy.hooks == ("warden",)
    assert _verdicts(policy) == {"open": True, "os.system": True, "subprocess.Popen": True,
                                 "exec": False, "compile": False, "object.__getattr__": False,
                                 "import": True}


def test_parse_early_return_then_raise_is_an_allowlist():
    policy = pg.parse_audit_hooks(EARLY_RETURN_HOOK)
    assert _verdicts(policy) == {"open": True, "os.system": True, "subprocess.Popen": True,
                                 "exec": False, "compile": False, "object.__getattr__": True,
                                 "import": True}


def test_parse_not_in_return_then_raise_is_a_denylist_of_that_set():
    # ``if ev not in X: return`` then ``raise``: only events IN X reach the raise -- a deny of X,
    # not an allowlist.  (Checked on CPython: this hook blocks open, lets exec through.)
    policy = pg.parse_audit_hooks(NARROWED_HOOK)
    assert policy.allow is None
    assert _verdicts(policy) == {"open": True, "os.system": True, "subprocess.Popen": False,
                                 "exec": False, "compile": False, "object.__getattr__": False,
                                 "import": False}


def test_parse_substring_in_hook_matches_events_containing_the_token():
    policy = pg.parse_audit_hooks(CONTAINS_HOOK)
    assert [m.contains for m in policy.deny] == [("socket", "ctypes")]
    assert _verdicts(policy, ("socket.connect", "socket.gethostbyname", "ctypes.dlopen", "open",
                              "exec")) == {"socket.connect": True, "socket.gethostbyname": True,
                                           "ctypes.dlopen": True, "open": False, "exec": False}


def test_parse_lambda_hook_with_exit_call():
    policy = pg.parse_audit_hooks(LAMBDA_HOOK)
    assert _verdicts(policy) == {"open": True, "os.system": False, "subprocess.Popen": False,
                                 "exec": False, "compile": False, "object.__getattr__": False,
                                 "import": True}


def test_parse_irreducible_hook_says_unknown_never_guesses():
    policy = pg.parse_audit_hooks(OPAQUE_HOOK)
    assert policy.unknown and "line 4" in policy.unknown[0]
    assert set(_verdicts(policy).values()) == {None}


def test_parse_without_hook_blocks_nothing_and_bad_source_is_loud():
    policy = pg.parse_audit_hooks("x = 1\n")
    assert policy.hooks == () and set(_verdicts(policy).values()) == {False}
    with pytest.raises(pg.GadgetError, match="does not parse"):
        pg.parse_audit_hooks("def broken(:\n")


def test_parse_reads_source_as_data_and_never_runs_it(tmp_path):
    sentinel = tmp_path / "ran"
    src = f"open({str(sentinel)!r}, 'w').write('x')\n" + DENY_HOOK
    policy = pg.parse_audit_hooks(src)
    assert policy.blocks("open") is True
    assert not sentinel.exists()


def test_rank_with_parsed_policy_is_precise():
    rows = _rows(pg.JailProfile(audit_policy=pg.parse_audit_hooks(ALLOW_HOOK)))
    assert rows["os-open-read"]["usable"] is False
    assert rows["os-open-read"]["reasons"] == ["route raises a blocked audit event: open"]
    assert rows["builtins-exec"]["usable"] is True        # exec/compile are on the allowlist
    assert rows["frame-selfref"]["usable"] is True        # object.__getattr__ allowed
    assert rows["environ-write"]["usable"] is True        # raises nothing
    # A hook that denies object.__getattr__ kills the gi_frame route but not the __globals__ route.
    deny_getattr = 'import sys\ndef h(e, a):\n    if e == "object.__getattr__":\n        raise X\nsys.addaudithook(h)\n'
    rows2 = _rows(pg.JailProfile(audit_policy=pg.parse_audit_hooks(deny_getattr)))
    assert rows2["frame-selfref"]["usable"] is False
    assert rows2["init-globals"]["usable"] is True
    assert rows2["os-system-cat"]["usable"] is True       # the parsed hook allows os.system


def test_rank_with_unknown_policy_penalises_without_blocking():
    rows = _rows(pg.JailProfile(audit_policy=pg.parse_audit_hooks(OPAQUE_HOOK)))
    row = rows["os-open-read"]
    assert row["usable"] is True
    assert row["reasons"] == ["audit hook verdict unknown for: open"]
    assert row["score"] == pg._BY_NAME["os-open-read"].base_rank - 10
    assert rows["environ-write"]["reasons"] == []


def test_cli_audit_and_rank_read_jail_source(tmp_path):
    src = tmp_path / "jail.py"
    src.write_text(ALLOW_HOOK)
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert pg.main(["audit", str(src), "--event", "open", "--event", "exec"]) == 0
    out = json.loads(buf.getvalue())
    assert out["hooks"] == ["warden"] and out["verdicts"] == {"open": True, "exec": False}
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert pg.main(["rank", "--jail-source", str(src), "--only-usable", "--json"]) == 0
    names = {r["name"] for r in json.loads(buf.getvalue())}
    assert "environ-write" in names and "os-open-read" not in names
    assert pg.main(["audit", str(tmp_path / "missing.py")]) == 2


# ===========================================================================================
#  Payload conformance on real CPython (our own interpreter, our own strings)
# ===========================================================================================

_CHILD = r"""
import os, subprocess, tempfile, asyncio.events, sys
payload = sys.stdin.read()
exec(payload, {"__builtins__": {}})
"""


def _run_in_child(payload: str, env: dict | None = None, *, child: str = _CHILD) -> bytes:
    child_env = {"PATH": os.environ.get("PATH", "")}
    child_env.update(env or {})
    proc = subprocess.run([sys.executable, "-I", "-c", child], input=payload.encode(),
                          capture_output=True, env=child_env, timeout=300)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    return proc.stdout


# The frame gadgets return objects rather than write output, so this child evaluates the payload
# under empty builtins and then (outside the payload, with real builtins) reports what came back.
_FRAME_CHILD = r"""
import sys
JAIL_MODULE_MARK = "jail-module-globals"
payload = sys.stdin.read()
def jail():
    ns = {"__builtins__": {}}
    if payload.startswith("EVAL:"):
        got = eval(compile(payload[5:], "<jail>", "eval"), ns)
        sys.stdout.write("%s|%s|%s" % (type(got).__name__, got.f_code.co_name, got.f_code.co_filename))
    else:
        exec(compile(payload, "<jail>", "exec"), ns)
        sys.stdout.write(str(ns["J"].get("JAIL_MODULE_MARK")))
jail()
"""


def test_frame_selfref_template_returns_the_running_frame_on_real_cpython():
    template = pg._BY_NAME["frame-selfref"].template
    payload = template.format(var="g", inner="_")
    assert _run_in_child("EVAL:" + payload, child=_FRAME_CHILD) == b"frame|<module>|<jail>"


def test_frame_walk_locals_reaches_the_jail_module_globals_on_real_cpython():
    # <jail> frame -> jail() -> the child's module frame, whose f_locals are its globals.
    assert _run_in_child(pg.frame_walk_locals(2), child=_FRAME_CHILD) == b"jail-module-globals"
    assert _run_in_child(pg.frame_walk_locals(1), child=_FRAME_CHILD) == b"None"  # jail()'s locals


def test_probe_payload_writes_its_marker_on_real_cpython_for_every_route():
    for index, route in enumerate(pji.CANDIDATE_ROUTES):
        marker = f"=PJ{index:02d}abc="
        payload = pji.probe_payload(route, marker)
        assert marker not in payload                      # never sent contiguously
        assert _run_in_child(payload) == marker.encode() + b"\n", route


def test_exploit_payloads_capture_env_and_file_on_real_cpython(tmp_path):
    secret = tmp_path / "flag"
    secret.write_bytes(b"CSCTF{real_file}\nsecond line\n")
    for route in (pji.Route("_wrap_close"), pji.Route("Popen", "os")):
        env_pl = pji.exploit_payload(route, "env", "=PJSa=", "=PJEb=", env_key="FLAG",
                                     banned=["FLAG", "environ", "write"])
        out = _run_in_child(env_pl, {"FLAG": "CSCTF{real_env}"})
        assert out == b"=PJSa=" + b"CSCTF{real_env}".hex().encode() + b"=PJEb=\n"
        file_pl = pji.exploit_payload(route, "file", "=PJSa=", "=PJEb=", path=str(secret))
        out = _run_in_child(file_pl)
        body = out[len(b"=PJSa="):-len(b"=PJEb=\n")]
        assert binascii.unhexlify(body) == secret.read_bytes()
        assert out.count(b"\n") == 1                       # hex keeps a multi-line secret on one line


# ===========================================================================================
#  A safe synthetic jail emulator (no real execution) for the loopback fake REPL
# ===========================================================================================

class _EvalError(Exception):
    pass


class _Fake:
    """A hand-built fake object: a bag of named attributes and/or a callable body."""

    def __init__(self, attrs=None, call=None):
        self.attrs = attrs or {}
        self.call = call


_EMPTY = object()  # stands in for the value of ``()``

# Where each class's __init__.__globals__ keeps the os module (None: the globals ARE os's dict).
# Mirrors real CPython; the conformance tests above prove the driver's routes on the real thing.
_FAKE_HOPS = {"_wrap_close": None, "Popen": "os", "_TemporaryFileCloser": "_os",
              "_TemporaryFileWrapper": "_os", "Handle": "os", "SomethingElse": None}


class _JailModel:
    """Models one sealed interpreter: which escape class is loaded, its module dict, env and files."""

    def __init__(self, loaded_class, env, files):
        self.out = []  # captured os.write payloads (bytes)

        def _write(fd, data):
            self.out.append(bytes(data))
            return len(data)

        def _open(path, flags):
            if path not in files:
                raise _EvalError("ENOENT")
            return _Fake(attrs={"__path__": path})

        def _read(fd, n):
            return files[fd.attrs["__path__"]][:n]

        osdict = {
            "write": _Fake(call=_write),
            "open": _Fake(call=_open),
            "read": _Fake(call=_read),
            "environ": dict(env),
        }
        hop = _FAKE_HOPS[loaded_class]
        globals_ = osdict if hop is None else {hop: _Fake(attrs={"__dict__": osdict})}
        init = _Fake(attrs={"__globals__": globals_})
        loaded = _Fake(attrs={"__name__": loaded_class, "__init__": init})
        subclasses = _Fake(call=lambda: [loaded])
        base = _Fake(attrs={"__subclasses__": subclasses})
        cls = _Fake(attrs={"__base__": base})
        self._empty_cls = _Fake(attrs={"__class__": cls})

    def _attr(self, obj, name):
        if obj is _EMPTY:
            if name == "__class__":
                return self._empty_cls.attrs["__class__"]
            raise _EvalError(f"no attr {name} on ()")
        if isinstance(obj, _Fake):
            if name in obj.attrs:
                return obj.attrs[name]
            raise _EvalError(f"no attr {name}")
        if isinstance(obj, str) and name == "encode":
            return _Fake(call=lambda *a: obj.encode(*a))
        if isinstance(obj, (bytes, bytearray)) and name == "hex":
            return _Fake(call=lambda: bytes(obj).hex())
        raise _EvalError(f"no attr {name} on {type(obj).__name__}")

    def _ev(self, node, env):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Tuple):
            if not node.elts:
                return _EMPTY
            return tuple(self._ev(e, env) for e in node.elts)
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise _EvalError(f"name {node.id}")
            return env[node.id]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._ev(node.left, env) + self._ev(node.right, env)
        if isinstance(node, ast.Attribute):
            return self._attr(self._ev(node.value, env), node.attr)
        if isinstance(node, ast.Subscript):
            obj = self._ev(node.value, env)
            key = self._ev(node.slice, env)
            try:
                return obj[key]
            except Exception as exc:  # IndexError/KeyError -> a jail fault
                raise _EvalError(str(exc))
        if isinstance(node, ast.Call):
            func = self._ev(node.func, env)
            args = [self._ev(a, env) for a in node.args]
            if isinstance(func, _Fake) and func.call is not None:
                return func.call(*args)
            raise _EvalError("not callable")
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
                raise _EvalError("unsupported compare")
            return self._ev(node.left, env) == self._ev(node.comparators[0], env)
        if isinstance(node, ast.ListComp):
            if len(node.generators) != 1:
                raise _EvalError("unsupported comprehension")
            gen = node.generators[0]
            if not isinstance(gen.target, ast.Name):
                raise _EvalError("unsupported comprehension target")
            results = []
            for item in self._ev(gen.iter, env):
                local = dict(env)
                local[gen.target.id] = item
                if all(self._ev(cond, local) for cond in gen.ifs):
                    results.append(self._ev(node.elt, local))
            return results
        raise _EvalError(f"unsupported node {type(node).__name__}")

    def run_line(self, src: str) -> bytes:
        self.out = []
        tree = ast.parse(src, mode="exec")
        env: dict = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                value = self._ev(stmt.value, env)
                for target in stmt.targets:
                    if not isinstance(target, ast.Name):
                        raise _EvalError("unsupported assignment target")
                    env[target.id] = value
            elif isinstance(stmt, ast.Expr):
                self._ev(stmt.value, env)
            else:
                raise _EvalError("unsupported statement")
        return b"".join(self.out)


class _JailServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, loaded_class, env, files, *, echo=False, greeting=b"", delay=0.0,
                 error_lines=1):
        self.loaded_class = loaded_class
        self.env = env
        self.files = files
        self.echo = echo
        self.error_lines = error_lines   # >1 models a jail that prints a multi-line traceback
        self.greeting = greeting
        self.delay = delay
        self.lines = []
        super().__init__(("127.0.0.1", 0), _JailHandler)
        self.port = self.server_address[1]
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()


class _JailHandler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        if srv.greeting:
            self.wfile.write(srv.greeting)
            self.wfile.flush()
        for raw in self.rfile:
            line = raw.rstrip(b"\n").decode("utf-8", "replace")
            if not line:
                continue
            srv.lines.append(line)
            if srv.delay:
                time.sleep(srv.delay)   # models a slow service (wall clock on purpose)
            if srv.echo:
                # A jail that never runs anything but echoes the offending line back.
                self.wfile.write(b"DENIED: " + line.encode() + b"\n")
                self.wfile.flush()
                continue
            model = _JailModel(srv.loaded_class, srv.env, srv.files)
            try:
                out = model.run_line(line)
            except (_EvalError, SyntaxError, ValueError):
                if srv.error_lines > 1:
                    self.wfile.write(b"Traceback (most recent call last):\n"
                                     + b"  File \"<jail>\", line 1\n" * (srv.error_lines - 2)
                                     + b"IndexError: list index out of range\n")
                else:
                    self.wfile.write(b"DENIED :: expression not authorised\n")
                self.wfile.flush()
                continue
            self.wfile.write(out if out else b"\n")
            self.wfile.flush()


@pytest.fixture
def jail_factory():
    servers = []

    def make(loaded_class="_wrap_close", env=None, files=None, **kw):
        srv = _JailServer(loaded_class, env or {"FLAG": "CSCTF{fake_flag_abc}"}, files or {}, **kw)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.stop()


def _session(srv, **kw):
    # Default framing on purpose: escape() must work with what Session gives by default ("line").
    # The read timeout is a generous upper bound on a loaded machine, not a measured quantity.
    return lh.Session("127.0.0.1", srv.port, min_interval=0, read_timeout=kw.pop("read_timeout", 120),
                      **kw)


# A minimal event profile so flagfmt can confirm the captured bytes.
def _profile():
    import datetime as dt

    from ctf import event

    return event.parse({
        "slug": "pyjail-test", "name": "pyjail test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.1"]},
    }, src="<test>")


class _Counter:
    """A deterministic nonce source: distinct per call."""

    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return f"n{self.n:04d}"


# ===========================================================================================
#  pyjail_interactive -- end to end through live_harness.Session against the loopback fake
# ===========================================================================================

def test_escape_env_route_through_a_default_session_captures_flag(jail_factory):
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{loopback_win}"})
    sess = _session(srv)
    assert sess.framing.mode == "line"
    with sess:
        result = pji.escape(sess, objective="env", env_key="FLAG", profile=_profile())
    assert result.route_class == "_wrap_close"
    assert result.captured == b"CSCTF{loopback_win}"
    assert result.flag == "CSCTF{loopback_win}" and result.flags_scanned is True
    assert result.submitted is False          # the driver never submits
    assert [s.kind for s in result.steps] == ["probe", "exploit"]
    assert result.lag == 0


def test_escape_walks_candidate_ladder_through_the_os_hop(jail_factory):
    # Only ``Popen`` is loaded; its globals hold os as a module, so the driver must hop __dict__.
    srv = jail_factory(loaded_class="Popen", env={"FLAG": "CSCTF{ladder}"})
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile())
    assert result.route_class == "Popen"
    assert result.flag == "CSCTF{ladder}"
    probes = [s for s in result.steps if s.kind == "probe"]
    assert [s.class_name for s in probes] == ["_wrap_close", "Popen"]
    assert probes[0].marker_seen is False and probes[1].marker_seen is True
    assert ".__dict__" in result.steps[-1].payload


def test_escape_reports_no_route_when_no_candidate_is_loaded(jail_factory):
    srv = jail_factory(loaded_class="SomethingElse", env={"FLAG": "CSCTF{unreached}"})
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile())
    assert result.route_class is None
    assert result.flag is None
    assert "no candidate class" in result.note
    assert len([s for s in result.steps if s.kind == "probe"]) == len(pji.CANDIDATE_ROUTES)
    assert "CSCTF{" not in result.captured.decode("utf-8", "replace")


def test_echoing_jail_cannot_fake_a_route(jail_factory):
    # The jail runs nothing and echoes every line back.  The marker is only ever built in-jail, so
    # an echo never contains it: no route may be claimed.
    srv = jail_factory(loaded_class="_wrap_close", echo=True)
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile(), nonce=_Counter())
    assert result.route_class is None
    assert all(not s.marker_seen for s in result.steps)
    assert len(srv.lines) == len(pji.CANDIDATE_ROUTES)
    for index, step in enumerate(result.steps):
        assert f"=PJ{index:02d}n{index + 1:04d}=" not in step.payload


def test_late_reply_is_attributed_to_its_own_probe_not_the_current_one(jail_factory):
    # The jail greets on connect and nobody reads the greeting, so every reply arrives one request
    # late.  Probe 1 (Popen, not loaded) receives probe 0's (_wrap_close) proof: the route is
    # _wrap_close, and the exploit's reply is collected one frame later.
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{late}"},
                       greeting=b"welcome to the jail\n")
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile(), nonce=_Counter())
    assert result.route_class == "_wrap_close"
    assert result.lag == 1
    assert "late reply" in result.note
    assert [s.kind for s in result.steps] == ["probe", "probe", "exploit", "resync"]
    assert result.steps[1].class_name == "Popen" and result.steps[1].marker_seen is False
    assert result.flag == "CSCTF{late}"


def test_stream_two_replies_behind_resyncs_by_exactly_two_frames(jail_factory):
    # A two-line greeting nobody reads: every reply arrives two requests late.  Probes 0 and 1 get
    # the greeting; probe 2 (_TemporaryFileCloser, not loaded) receives probe 0's proof.  The
    # exploit's own reply is then two frames behind and must be read by two resyncs, not one.
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{lag_two}"},
                       greeting=b"welcome\nto the jail\n")
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile(), nonce=_Counter())
    assert result.route_class == "_wrap_close"
    assert result.lag == 2
    assert "2 reply(ies) behind" in result.note
    assert [s.kind for s in result.steps] == ["probe", "probe", "probe", "exploit", "resync", "resync"]
    assert [s.marker_seen for s in result.steps] == [False, False, False, False, False, True]
    assert result.flag == "CSCTF{lag_two}"


def test_multiline_traceback_breaks_the_frame_count_loudly_never_falsely(jail_factory):
    # Known limit: a failed probe answered by a 3-line traceback shifts the stream by 3 frames, not 1.
    # The route is still attributed correctly, but the exploit reply is not reached in `lag` frames:
    # the driver must say so and report no flag (never a fabricated one).
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{unreached_tb}"},
                       greeting=b"welcome\n", error_lines=3)
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile(), nonce=_Counter())
    assert result.route_class == "_wrap_close" and result.lag == 1
    assert result.flag is None and result.flag_candidates == []
    assert "no marker-delimited output was captured" in result.note
    assert "multi-frame errors" in result.note
    # What was kept is the stale traceback frame, not the secret.
    assert b'File "<jail>"' in result.captured and b"CSCTF{" not in result.captured


def test_slow_jail_is_read_by_framing_not_by_a_quiet_window(jail_factory):
    # A service that answers well after any short quiet window must still be read correctly: the
    # Session waits for the line terminator.  Lower bound only on wall-clock time.
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{slow}"}, delay=0.5)
    t0 = time.monotonic()
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", profile=_profile())
    assert time.monotonic() - t0 >= 1.0             # two delayed replies really were waited for
    assert result.route_class == "_wrap_close" and result.flag == "CSCTF{slow}"


def test_escape_file_objective_reads_a_multiline_file_in_band(jail_factory):
    content = b"CSCTF{file_route}\nsecond line\n"
    srv = jail_factory(loaded_class="_wrap_close", files={"/flag": content})
    with _session(srv) as sess:
        result = pji.escape(sess, objective="file", path="/flag", profile=_profile())
    assert result.route_class == "_wrap_close"
    assert result.captured == content
    assert result.flag == "CSCTF{file_route}"


def test_escape_survives_substring_denylist_end_to_end(jail_factory):
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{evaded}"})
    banned = ["write", "environ", "_wrap_close", "FLAG"]
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", env_key="FLAG", banned=banned, profile=_profile())
    assert result.flag == "CSCTF{evaded}"
    for step in result.steps:
        for token in banned:
            assert token not in step.payload


def test_jail_profile_banned_substrings_are_evaded_too(jail_factory):
    srv = jail_factory(loaded_class="_wrap_close", env={"FLAG": "CSCTF{jailprof}"})
    jail = pg.JailProfile(banned_substrings=("environ", "write"))
    with _session(srv) as sess:
        result = pji.escape(sess, objective="env", jail=jail, profile=_profile())
    assert result.flag == "CSCTF{jailprof}"
    assert all("environ" not in s.payload and "write" not in s.payload for s in result.steps)


class _Recorder:
    def __init__(self, reply=b"\n"):
        self.sent = []
        self.reply = reply

    def request(self, payload):
        self.sent.append(payload)
        return self.reply


def test_jail_profile_that_blocks_the_route_is_refused_before_sending():
    rec = _Recorder()
    with pytest.raises(pji.EscapeError, match="subclass-by-name"):
        pji.escape(rec, objective="env", profile=None,
                   jail=pg.JailProfile(banned_features=frozenset({"comprehension"})))
    assert rec.sent == []


def test_jail_profile_that_blocks_the_file_objective_output_is_refused_before_sending():
    # os.open raises the 'open' audit event: an audit-hooked jail blocks os-open-read, so the file
    # objective must be refused before any payload goes out ...
    for jail in (pg.JailProfile(audit_hook=True),
                 pg.JailProfile(audit_policy=pg.parse_audit_hooks(ALLOW_HOOK))):
        rec = _Recorder()
        with pytest.raises(pji.EscapeError, match="os-open-read.*open"):
            pji.escape(rec, objective="file", profile=None, jail=jail)
        assert rec.sent == []
    # ... while the env objective (environ-write, no audit event) proceeds under the same hook.
    rec = _Recorder()
    result = pji.escape(rec, objective="env", profile=None, jail=pg.JailProfile(audit_hook=True))
    assert len(rec.sent) == len(pji.CANDIDATE_ROUTES) and result.route_class is None


def test_unevadable_ban_on_an_attribute_name_is_refused_before_sending():
    rec = _Recorder()
    with pytest.raises(pji.EscapeError, match="__globals__"):
        pji.escape(rec, objective="env", profile=None, banned=["__globals__"])
    assert rec.sent == []


def _bytes_literals(src: str) -> bytes:
    """Join the payload's bytes literals in source order (what the jail's ``+`` would build)."""
    nodes = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Constant) and isinstance(n.value, bytes)]
    return b"".join(n.value for n in sorted(nodes, key=lambda n: (n.lineno, n.col_offset)))


class _Proving:
    """A scripted transport: answers the first probe with its marker and the exploit with a capture."""

    def __init__(self, secret: bytes):
        self.sent = []
        self.secret = secret

    def request(self, payload):
        src = payload.decode()
        self.sent.append(src)
        joined = _bytes_literals(src)          # probe: MARKER+b"\n"; exploit: START+END+b"\n"
        if len(self.sent) == 1:
            return joined
        body = joined.rstrip(b"\n")
        cut = body.index(b"=PJE")
        return body[:cut] + self.secret.hex().encode() + body[cut:]


def test_no_event_profile_means_no_scan_and_says_so():
    result = pji.escape(_Proving(b"CSCTF{x}"), objective="env", profile=None)
    assert result.route_class == "_wrap_close"
    assert result.captured == b"CSCTF{x}"
    assert result.flag is None and result.flag_candidates == [] and result.flags_scanned is False
    assert "flag format not checked: no event profile given" in result.note


def test_markers_are_distinct_within_a_run_and_random_across_runs():
    # Even a constant nonce source yields one distinct marker per probe (the tag differs) ...
    rec = _Recorder()
    result = pji.escape(rec, objective="env", profile=None, nonce=lambda: "same")
    markers = [re.findall(rb"=PJ[0-9A-Za-z]+=", _bytes_literals(p.decode()))[0] for p in rec.sent]
    assert len(markers) == len(pji.CANDIDATE_ROUTES) == len(set(markers))
    assert result.route_class is None
    # ... and the default nonce differs between runs, so a stale reply from run 1 proves nothing in run 2.
    rec2 = _Recorder()
    pji.escape(rec2, objective="env", profile=None)
    rec3 = _Recorder()
    pji.escape(rec3, objective="env", profile=None)
    assert rec2.sent[0] != rec3.sent[0]
    with pytest.raises(pji.EscapeError, match="alphanumeric"):
        pji.escape(_Recorder(), objective="env", profile=None, nonce=lambda: "bad nonce")


def test_escape_rejects_a_non_bytes_transport_reply():
    class _Bad:
        def request(self, payload):
            return "not-bytes"

    with pytest.raises(pji.EscapeError):
        pji.escape(_Bad(), objective="env", profile=None)


def test_escape_requires_the_profile_argument():
    with pytest.raises(TypeError):
        pji.escape(_Recorder(), objective="env")  # profile is keyword-required


def test_module_opens_no_socket_of_its_own():
    src = open(pji.__file__, encoding="utf-8").read()
    assert "import socket" not in src and "create_connection" not in src
    assert not hasattr(pji, "LineReplTransport")


def test_cli_dry_run_prints_payloads_without_contiguous_markers():
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert pji.main(["--json", "--class-name", "_wrap_close", "--class-name", "Popen"]) == 0
    plan = json.loads(buf.getvalue())["plan"]
    assert [row["kind"] for row in plan] == ["probe", "probe", "exploit"]
    for row in plan:
        markers = re.findall(rb"=PJ[0-9A-Za-z]+=", _bytes_literals(row["payload"]))
        assert len(markers) == (1 if row["kind"] == "probe" else 2)
        for marker in markers:
            assert marker.decode() not in row["payload"]
    assert pji.main(["--ban-substr", "__init__"]) == 2
