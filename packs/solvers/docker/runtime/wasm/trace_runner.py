#!/usr/bin/env python3
"""ctf-runtime-wasm runner (B-242): one WebAssembly module under wasmtime, fuel-bounded.

Runs INSIDE the ctf-runtime-wasm container (no network, no host mount, read-only root); the artifact
is the tar member the entry script unpacked into /work. Never run on the host against a delivered
file: the container is the boundary, this script is not one.

    trace_runner.py --artifact FILE --fuel N [--seconds S] [--max-events N] [--probe-hex HEX]...

What it does, all of it counted against one budget of wasmtime fuel (roughly one unit per
instruction, plus what wasmtime charges to set an instance up). Each instantiation and the call made
on it may use an eighth of the budget, so one function that never returns does not leave the rest
untraced; a call that runs out traps and the trace says so:
  - validates and compiles the module, lists its imports and exports (the entry points);
  - instantiates it with every function import stubbed: a stub records the call and its arguments
    and returns zeros. WASI imports get wasmtime's WASI with no preopened directory, no
    environment, the probe as stdin, and stdout/stderr captured;
  - calls `_start` once per probe (a WASI command), and every other exported function that takes
    only numbers: once with zeros, and once per probe with the probe written into a freshly grown
    memory page and its address (and length) passed as the first i32 argument(s);
  - after each call, reports the printable strings that are in linear memory now and were not
    there right after instantiation (a constant the module decoded at run time).

Output: one line on stdout, `@@CTF-RUNTIME-TRACE@@ ` + JSON (schema 1, every value a bounded string).
"""
import argparse
import json
import os
import re
import sys
import tempfile

import wasmtime

MARKER = "@@CTF-RUNTIME-TRACE@@ "
MAX_TEXT = 2048            # characters of one reported value
MAX_STRINGS = 256          # strings reported
MAX_ENTRIES = 256          # entry points listed
MAX_CALL_TARGETS = 48      # exported functions called
MAX_SCAN = 16 << 20        # bytes of linear memory searched for strings
MIN_STRING = 5
SHARE = 8                  # one instantiation and its call may use 1/SHARE of the budget
PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,512}" % MIN_STRING)
WASI_MODULES = ("wasi_snapshot_preview1", "wasi_unstable")
NUMERIC = ("i32", "i64", "f32", "f64")
SKIP_EXPORTS = ("_start", "_initialize", "__wasm_call_ctors", "__wasm_apply_data_relocs")


def clip(value):
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "...[cut]"


def _wasmtime_version():
    try:
        from importlib.metadata import version
        return version("wasmtime")
    except Exception:  # noqa: BLE001 - the version is a label, never a reason to fail a trace
        return "unknown"


class Trace:
    def __init__(self, fuel, max_events):
        self.doc = {"schema": 1, "runtime": "wasm", "runtime_version": "wasmtime-py " + _wasmtime_version(),
                    "status": "ok",
                    "fuel": {"kind": "instructions", "limit": fuel, "used": 0, "exhausted": False},
                    "entries": [], "events": [], "strings": [], "notes": [], "truncated": False}
        self.max_events = max_events
        self._seen = set()

    def event(self, kind, **fields):
        if len(self.doc["events"]) >= self.max_events:
            self.doc["truncated"] = True
            return
        row = {"kind": kind}
        row.update({k: clip(v) for k, v in fields.items()})
        self.doc["events"].append(row)

    def string(self, text):
        text = clip(text)
        if text in self._seen:
            return
        if len(self.doc["strings"]) >= MAX_STRINGS:
            self.doc["truncated"] = True
            return
        self._seen.add(text)
        self.doc["strings"].append(text)

    def note(self, text):
        self.doc["notes"].append(clip(text))

    def partial(self):
        if self.doc["status"] == "ok":
            self.doc["status"] = "partial"

    def emit(self):
        sys.stdout.write(MARKER + json.dumps(self.doc, sort_keys=True) + "\n")
        sys.stdout.flush()


def signature(ty):
    return "(%s) -> (%s)" % (", ".join(str(p) for p in ty.params), ", ".join(str(r) for r in ty.results))


def zero(valtype):
    name = str(valtype)
    if name in ("i32", "i64"):
        return 0
    if name in ("f32", "f64"):
        return 0.0
    return None


def out_of_fuel(err):
    return "fuel" in str(err).lower()


class Budget:
    """The one fuel budget. A session is handed a share and charged for what it used of it."""

    def __init__(self, trace, limit):
        self.trace, self.limit, self.left = trace, limit, limit
        self.share = max(1, limit // SHARE)

    def grant(self):
        return min(self.left, self.share)

    def charge(self, used):
        self.left = max(0, self.left - used)
        self.trace.doc["fuel"]["used"] = self.limit - self.left
        if self.left <= 0:
            self.trace.doc["fuel"]["exhausted"] = True
        return used


class Session:
    """One instantiation: its own store (holding its share of the fuel), linker and instance."""

    def __init__(self, engine, module, trace, budget, stdin=b""):
        self.trace, self.budget, self.module = trace, budget, module
        self.store = wasmtime.Store(engine)
        self.mark = budget.grant()
        self.store.set_fuel(self.mark)
        self.tmp = tempfile.mkdtemp(prefix="wasm-run-")
        self.out_path = os.path.join(self.tmp, "stdout")
        self.err_path = os.path.join(self.tmp, "stderr")
        self.linker = wasmtime.Linker(engine)
        if any(imp.module in WASI_MODULES for imp in module.imports):
            in_path = os.path.join(self.tmp, "stdin")
            with open(in_path, "wb") as fh:
                fh.write(stdin)
            wasi = wasmtime.WasiConfig()
            wasi.argv = ["artifact"]
            wasi.stdin_file = in_path
            wasi.stdout_file = self.out_path
            wasi.stderr_file = self.err_path
            self.store.set_wasi(wasi)
            self.linker.define_wasi()
        for imp in module.imports:
            if imp.module in WASI_MODULES:
                continue
            ty = imp.type
            label = "%s.%s" % (imp.module, imp.name)
            if isinstance(ty, wasmtime.FuncType):
                self.linker.define_func(imp.module, imp.name, ty, self._stub(label, ty))
            elif isinstance(ty, wasmtime.MemoryType):
                self.linker.define(self.store, imp.module, imp.name, wasmtime.Memory(self.store, ty))
            elif isinstance(ty, wasmtime.GlobalType):
                self.linker.define(self.store, imp.module, imp.name,
                                   wasmtime.Global(self.store, ty, zero(ty.content)))
            elif isinstance(ty, wasmtime.TableType):
                self.linker.define(self.store, imp.module, imp.name, wasmtime.Table(self.store, ty, None))
            else:
                raise wasmtime.WasmtimeError("import %s has a kind this runner does not provide" % label)
        self.exports = {}

    def instantiate(self):
        self.exports = self.linker.instantiate(self.store, self.module).exports(self.store)

    def _stub(self, label, ty):
        zeros = [zero(r) for r in ty.results]

        def stub(*args):
            self.trace.event("import_call", name=label, args=", ".join(str(a) for a in args))
            if not zeros:
                return None
            return zeros[0] if len(zeros) == 1 else zeros
        return stub

    def charge(self):
        """Charge the budget for the fuel this session used since its last charge."""
        now = self.store.get_fuel()
        used, self.mark = self.mark - now, now
        return self.budget.charge(used)

    def memory(self):
        for name in ("memory",) + tuple(sorted(self.exports.keys())):
            item = self.exports.get(name)
            if isinstance(item, wasmtime.Memory):
                return item
        return None

    def strings(self):
        mem = self.memory()
        if mem is None:
            return set()
        size = min(mem.data_len(self.store), MAX_SCAN)
        data = bytes(mem.read(self.store, 0, size))
        return {m.group().decode("ascii") for m in PRINTABLE.finditer(data)}

    def output(self):
        for stream, path in (("stdout", self.out_path), ("stderr", self.err_path)):
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    text = fh.read(MAX_TEXT * 4).decode("utf-8", "replace")
                if text:
                    self.trace.event("output", stream=stream, text=text)
                    for line in text.splitlines():
                        if line.strip():
                            self.trace.string(line.strip())


def run(args):
    trace = Trace(args.fuel, args.max_events)
    budget = Budget(trace, args.fuel)
    probes = [bytes.fromhex(p) for p in args.probe_hex] or [b""]
    with open(args.artifact, "rb") as fh:
        data = fh.read()
    config = wasmtime.Config()
    config.consume_fuel = True
    engine = wasmtime.Engine(config)
    try:
        module = wasmtime.Module(engine, data)
    except wasmtime.WasmtimeError as e:
        trace.doc["status"] = "error"
        trace.event("error", name="load", text=str(e))
        return trace
    for imp in module.imports:
        trace.event("import", name="%s.%s" % (imp.module, imp.name), text=type(imp.type).__name__)
    targets = []
    for exp in module.exports:
        if isinstance(exp.type, wasmtime.FuncType):
            if len(trace.doc["entries"]) < MAX_ENTRIES:
                trace.doc["entries"].append({"name": clip(exp.name), "signature": signature(exp.type)})
            else:
                trace.doc["truncated"] = True
            targets.append((exp.name, exp.type))

    def open_session(stdin=b""):
        """A fresh instance holding its share of the fuel, or None when it cannot be made (reported)."""
        if budget.left <= 0:
            return None
        try:
            session = Session(engine, module, trace, budget, stdin)
        except wasmtime.WasmtimeError as e:
            trace.doc["status"] = "error"
            trace.event("error", name="instantiate", text=str(e))
            return None
        try:
            session.instantiate()
        except (wasmtime.WasmtimeError, wasmtime.Trap) as e:
            session.charge()
            if out_of_fuel(e):
                trace.event("error", name="instantiate", text="the start function ran out of fuel")
                trace.partial()
            else:
                trace.doc["status"] = "error"
                trace.event("error", name="instantiate", text=str(e).splitlines()[0])
            return None
        session.charge()
        return session

    def call(session, name, values, shown, baseline):
        fn = session.exports[name]
        try:
            result = fn(session.store, *values)
            trace.event("call", name=name, args=shown, result=str(result), fuel=str(session.charge()))
        except wasmtime.ExitTrap as e:
            trace.event("call", name=name, args=shown, result="exit %s" % e.code, fuel=str(session.charge()))
        except (wasmtime.Trap, wasmtime.WasmtimeError) as e:
            used = session.charge()
            why = "out of fuel" if out_of_fuel(e) else str(e).splitlines()[0]
            trace.event("call", name=name, args=shown, error=why, fuel=str(used))
            trace.partial()
        session.output()
        for text in sorted(session.strings() - baseline):
            trace.string(text)

    if open_session() is None:        # does it instantiate at all?
        trace.partial()
        return trace
    if "_start" in dict(targets):
        for i, probe in enumerate(probes):
            session = open_session(probe + b"\n")
            if session is None:
                trace.partial()
                break
            call(session, "_start", [], "stdin=probe %d" % i, session.strings())
    called = 0
    for name, ty in targets:
        if name in SKIP_EXPORTS:
            continue
        if any(str(p) not in NUMERIC for p in ty.params):
            trace.note("%s takes a non-numeric parameter: not called" % name)
            continue
        if called >= MAX_CALL_TARGETS:
            trace.note("more than %d exported functions: the rest were not called" % MAX_CALL_TARGETS)
            trace.partial()
            break
        called += 1
        plans = [("zeros", None)]
        if any(str(p) == "i32" for p in ty.params):
            plans += [("probe %d" % i, p) for i, p in enumerate(probes) if p]
        for shown, probe in plans:
            session = open_session()
            if session is None:
                trace.partial()
                break
            if "_initialize" in session.exports:
                try:
                    session.exports["_initialize"](session.store)
                except (wasmtime.Trap, wasmtime.WasmtimeError) as e:
                    trace.event("error", name="_initialize", text=str(e).splitlines()[0])
                session.charge()
            baseline = session.strings()
            values = [zero(p) for p in ty.params]
            if probe is not None:
                mem = session.memory()
                if mem is None:
                    trace.note("%s: no exported memory to place a probe in" % name)
                    continue
                try:
                    old_pages = mem.grow(session.store, 1)
                except (wasmtime.WasmtimeError, wasmtime.Trap):
                    trace.note("%s: memory cannot grow, so no probe was placed" % name)
                    continue
                addr = old_pages * 65536
                mem.write(session.store, probe[:65000] + b"\x00", addr)
                slots = [i for i, p in enumerate(ty.params) if str(p) == "i32"]
                values[slots[0]] = addr
                if len(slots) > 1:
                    values[slots[1]] = len(probe)
                shown = "%s at %d" % (shown, addr)
                baseline = session.strings()
            call(session, name, values, shown, baseline)
        if budget.left <= 0:
            trace.partial()
            break
    return trace


def main(argv):
    ap = argparse.ArgumentParser(description="ctf-runtime-wasm runner")
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
