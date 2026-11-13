#!/usr/bin/env python3
"""ctf-runtime-python runner (B-242): one .pyc (or .py) on the CPython that made it, opcode-bounded.

Runs INSIDE a ctf-runtime-python container of the matching Python version (no network, no host
mount, read-only root). Nothing here is a security boundary: the container is. Never run on the host
against a delivered file. Written for Python 3.8 to 3.14, standard library only.

    trace_runner.py --artifact FILE --fuel N [--seconds S] [--max-events N] [--probe-hex HEX]...

What it does:
  - a .pyc must carry this interpreter's magic number: anything else is reported with both magic
    numbers and not loaded (the caller picks the image of the matching version). The code object is
    unmarshalled here, inside the container, never on the host;
  - lists every function and class body in the code object (the entry points) and the string
    constants it carries, which no decompiler is needed for;
  - runs the module as __main__ once per probe while it reads input (the probe is sys.argv[1],
    input() and sys.stdin), with stdout/stderr captured and every import and open() recorded;
  - fuel is bytecode instructions of the artifact and what it imports (not of this runner). On
    Python 3.12+ sys.monitoring counts them and the stop is raised again at every further
    instruction, so Python code that catches it cannot go on. On 3.8 to 3.11 a trace function
    counts them (frame.f_trace_opcodes), and CPython turns tracing off once it raises, so there code
    that swallows the stop is no longer counted. Code that spends its time inside one C call (a
    sleep, a pathological regex) executes no instruction at all. In both cases the container's own
    time limit ends the run, and no trace comes back. One run or call may use an eighth of the
    fuel, so a function that never returns does not leave the rest untraced;
  - reports the module globals left behind (a string built at run time shows up here) and calls each
    module-level function that takes at most one positional argument (once, or once per probe).

Output: one line on stdout, `@@CTF-RUNTIME-TRACE@@ ` + JSON (schema 1, every value a bounded string).
"""
import argparse
import builtins
import importlib.util
import io
import json
import marshal
import sys
import threading
import types

MARKER = "@@CTF-RUNTIME-TRACE@@ "
MAX_TEXT = 2048
MAX_STRINGS = 256
MAX_ENTRIES = 256
MAX_CALLS = 64
MAX_CODE_OBJECTS = 512
MIN_CONST = 4
SHARE = 8
RUNNER_FILE = __file__
MONITORING = getattr(sys, "monitoring", None)       # Python 3.12+
TOOL_ID = 0                                          # sys.monitoring.DEBUGGER_ID
REAL_STDOUT = sys.stdout
REAL_OPEN = builtins.open
REAL_IMPORT = builtins.__import__
REAL_INPUT = builtins.input


def clip(value):
    try:
        text = value if isinstance(value, str) else repr(value)
    except Exception:  # noqa: BLE001 - a hostile __repr__ must not end the trace
        text = "<unprintable %s>" % type(value).__name__
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "...[cut]"


class OutOfFuel(BaseException):
    """The whole budget is spent."""


class OutOfShare(BaseException):
    """One run or call used its share of the budget."""


class Trace:
    def __init__(self, fuel, max_events):
        self.doc = {"schema": 1, "runtime": "python",
                    "runtime_version": "%d.%d.%d" % sys.version_info[:3], "status": "ok",
                    "fuel": {"kind": "instructions", "limit": fuel, "used": 0, "exhausted": False},
                    "entries": [], "events": [], "strings": [], "notes": [], "truncated": False}
        self.max_events = max_events
        self._seen = set()
        self.cap = 0
        self._registered = False

    def event(self, kind, **fields):
        if len(self.doc["events"]) >= self.max_events:
            self.doc["truncated"] = True
            return
        row = {"kind": kind}
        row.update({k: clip(v) for k, v in fields.items()})
        self.doc["events"].append(row)

    def string(self, text):
        if not isinstance(text, str) or not text:
            return
        text = clip(text)
        if text in self._seen:
            return
        if len(self.doc["strings"]) >= MAX_STRINGS:
            self.doc["truncated"] = True
            return
        self._seen.add(text)
        self.doc["strings"].append(text)

    def entry(self, name, sig):
        if len(self.doc["entries"]) >= MAX_ENTRIES:
            self.doc["truncated"] = True
            return
        self.doc["entries"].append({"name": clip(name), "signature": clip(sig)})

    def partial(self):
        if self.doc["status"] == "ok":
            self.doc["status"] = "partial"

    def emit(self):
        REAL_STDOUT.write(MARKER + json.dumps(self.doc, sort_keys=True) + "\n")
        REAL_STDOUT.flush()

    # ------------------------------------------------------------------ fuel
    # The runner's own instructions are not charged (code whose co_filename is this file): only what
    # the artifact, and the modules it imports, execute.
    def _count(self):
        fuel = self.doc["fuel"]
        fuel["used"] += 1
        if fuel["used"] >= fuel["limit"]:
            fuel["exhausted"] = True
            raise OutOfFuel()
        if fuel["used"] >= self.cap:
            raise OutOfShare()

    def _tick(self, code, offset):            # sys.monitoring INSTRUCTION callback (Python 3.12+)
        if code.co_filename != RUNNER_FILE:
            self._count()

    def tracer(self, frame, what, arg):       # sys.settrace function (Python 3.8 to 3.11)
        if what == "call":
            if frame.f_code.co_filename == RUNNER_FILE:
                return None
            frame.f_trace_opcodes = True
            return self.tracer
        if what == "opcode":
            self._count()
        return self.tracer

    def _counting(self, on):
        if MONITORING is not None:
            if on and not self._registered:
                MONITORING.use_tool_id(TOOL_ID, "ctf-runtime-trace")
                MONITORING.register_callback(TOOL_ID, MONITORING.events.INSTRUCTION, self._tick)
                self._registered = True
            MONITORING.set_events(TOOL_ID, MONITORING.events.INSTRUCTION if on else 0)
        else:
            threading.settrace(self.tracer if on else None)
            sys.settrace(self.tracer if on else None)

    def guarded(self, name, shown, fn, report):
        """Run fn() under the instruction counter; returns False when the whole budget is spent."""
        fuel = self.doc["fuel"]
        if fuel["used"] >= fuel["limit"]:
            return False
        self.cap = fuel["used"] + max(1, fuel["limit"] // SHARE)
        self._counting(True)
        try:
            result = fn()
        except OutOfFuel:
            self._failed(name, shown, "out of fuel", report)
            return False
        except OutOfShare:
            self._failed(name, shown, "stopped: it used its share of the fuel", report)
            return True
        except SystemExit as e:
            self.event("exit", text=str(e.code))
            return True
        except BaseException as e:  # noqa: BLE001 - whatever the artifact raises is a finding
            self._failed(name, shown, "%s: %s" % (type(e).__name__, e), report)
            return True
        finally:
            self._counting(False)
        if report:
            self.event("call", name=name, args=shown, result=self.render(result))
        return True

    def _failed(self, name, shown, why, report):
        if report:
            self.event("call", name=name, args=shown, error=why)
        else:
            self.event("error", name=name, args=shown, text=why)
        self.partial()

    def render(self, value):
        if isinstance(value, str):
            self.string(value)
            return value
        if isinstance(value, (bytes, bytearray)):
            try:
                text = bytes(value).decode("ascii")
            except UnicodeDecodeError:
                return "hex:" + bytes(value).hex()[:MAX_TEXT]
            if text.isprintable():
                self.string(text)
                return text
            return "hex:" + bytes(value).hex()[:MAX_TEXT]
        if value is None or isinstance(value, (bool, int, float)):
            return str(value)
        if isinstance(value, (list, tuple, set, frozenset)) and len(value) <= 64:
            return "[" + ", ".join(self.render(v) for v in list(value)) + "]"
        if isinstance(value, dict) and len(value) <= 64:
            return "{" + ", ".join("%s: %s" % (self.render(k), self.render(v)) for k, v in value.items()) + "}"
        return "<%s>" % type(value).__name__


def load_code(data, trace):
    """The module's code object, or None (reported)."""
    if data[2:4] == b"\r\n":
        if data[:4] != importlib.util.MAGIC_NUMBER:
            trace.doc["status"] = "error"
            trace.event("error", name="load", text="this .pyc carries magic %d; this interpreter (Python %d.%d) "
                        "reads magic %d" % (int.from_bytes(data[:2], "little"), sys.version_info[0],
                                            sys.version_info[1],
                                            int.from_bytes(importlib.util.MAGIC_NUMBER[:2], "little")))
            return None
        try:
            code = marshal.loads(data[16:])
        except (ValueError, EOFError, TypeError) as e:
            trace.doc["status"] = "error"
            trace.event("error", name="load", text="unmarshal failed: %s" % e)
            return None
        if not isinstance(code, types.CodeType):
            trace.doc["status"] = "error"
            trace.event("error", name="load", text="the .pyc body is a %s, not a code object" % type(code).__name__)
            return None
        return code
    try:
        return compile(data, "artifact.py", "exec")
    except (SyntaxError, ValueError) as e:
        trace.doc["status"] = "error"
        trace.event("error", name="load", text="%s: %s" % (type(e).__name__, e))
        return None


def inventory(code, trace):
    todo, n = [(code, "")], 0
    while todo:
        co, prefix = todo.pop(0)
        n += 1
        if n > MAX_CODE_OBJECTS:
            trace.doc["truncated"] = True
            break
        name = prefix + co.co_name if prefix else co.co_name
        if co is not code:
            trace.entry(name, "code/%d" % co.co_argcount)
        for const in co.co_consts:
            if isinstance(const, types.CodeType):
                todo.append((const, "" if co is code else name + "."))
            elif isinstance(const, str) and len(const) >= MIN_CONST:
                trace.string(const)
            elif isinstance(const, bytes) and len(const) >= MIN_CONST:
                trace.render(const)


def run(args):
    trace = Trace(args.fuel, args.max_events)
    probes = [bytes.fromhex(p).decode("utf-8", "replace") for p in args.probe_hex] or [""]
    with REAL_OPEN(args.artifact, "rb") as fh:
        data = fh.read()
    code = load_code(data, trace)
    if code is None:
        return trace
    inventory(code, trace)

    def spy_import(name, *a, **kw):
        trace.event("import", name=name)
        return REAL_IMPORT(name, *a, **kw)

    def spy_open(file, *a, **kw):
        trace.event("open", name=file)
        return REAL_OPEN(file, *a, **kw)

    calls = 0
    for p, probe in enumerate(probes):
        state = {"input_used": False}

        def fake_input(prompt=""):
            state["input_used"] = True
            if prompt:
                sys.stdout.write(str(prompt))
            if state.get("read"):
                raise EOFError("EOF when reading a line")
            state["read"] = True
            return probe

        class Stdin(io.StringIO):
            def read(self, *a):
                state["input_used"] = True
                return io.StringIO.read(self, *a)

            def readline(self, *a):
                state["input_used"] = True
                return io.StringIO.readline(self, *a)

        class Argv(list):
            def __getitem__(self, i):
                state["input_used"] = True
                return list.__getitem__(self, i)

        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr, sys.stdin = out, err, Stdin(probe + "\n")
        sys.argv = Argv(["artifact.py", probe])
        builtins.input, builtins.open, builtins.__import__ = fake_input, spy_open, spy_import
        scope = {"__name__": "__main__", "__builtins__": builtins, "__file__": "artifact.py"}
        baseline = set(scope)

        def flush():
            for stream, buf in (("stdout", out), ("stderr", err)):
                text = buf.getvalue()
                buf.seek(0)
                buf.truncate()
                if text:
                    trace.event("output", stream=stream, text=text)
                    for line in text.splitlines():
                        if line.strip():
                            trace.string(line.strip())

        try:
            alive = trace.guarded("module", "probe %d" % p, lambda: exec(code, scope), False)
            flush()
            unary = False
            for name in sorted(k for k in scope if k not in baseline and not k.startswith("__")):
                if not alive:
                    break
                value = scope[name]
                if isinstance(value, types.FunctionType):
                    n = value.__code__.co_argcount - len(value.__defaults__ or ())
                    unary = unary or n == 1
                    if not (n == 1 or (n == 0 and p == 0)):
                        continue
                    if calls >= MAX_CALLS:
                        trace.partial()
                        continue
                    calls += 1
                    fn = (lambda f=value: f(probe)) if n == 1 else (lambda f=value: f())
                    alive = trace.guarded(name, "probe %d" % p if n == 1 else "", fn, True)
                    flush()
                elif isinstance(value, (type, types.ModuleType)):
                    continue
                elif p == 0 or state["input_used"]:
                    trace.event("global", name=name, value=trace.render(value))
        finally:
            sys.stdout, sys.stderr, sys.stdin = sys.__stdout__, sys.__stderr__, sys.__stdin__
            builtins.input, builtins.open, builtins.__import__ = REAL_INPUT, REAL_OPEN, REAL_IMPORT
        if not alive or (not state["input_used"] and not unary):
            break
    if trace.doc["fuel"]["exhausted"]:
        trace.partial()
    return trace


def main(argv):
    ap = argparse.ArgumentParser(description="ctf-runtime-python runner")
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--deps", default="")
    ap.add_argument("--fuel", type=int, required=True)
    ap.add_argument("--seconds", type=float, default=0.0)
    ap.add_argument("--max-events", type=int, default=512)
    ap.add_argument("--probe-hex", action="append", default=[])
    args = ap.parse_args(argv)
    if args.fuel <= 0:
        ap.error("--fuel must be positive")
    run(args).emit()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
