"""Worker process of the Script speed solver for Days 11 to 31 (2026-10-31 night).

Started by script_pool.start() as `python -I script_worker.py` (no fork: a plain child with its own imports).
It imports the speed reader (when one is configured, see below) and the SHIPPED lane solver
(solvers/script-analysis/analyze.py, loaded the way tools/run.py loads it), warms both, and then answers jobs
on its stdin/stdout pipes:

    job   (path of the delivery file, [(container or None, member, [(answer_id, raw question)])])
    reply {answer_id: value}

Each specimen is read by the configured speed reader (the speed path, no guess); a specimen it does not answer whole is
handed to the shipped solver on that one member (solve_set with the member's own bytes, exactly as split_sets
would expand it), and only its plain answers are kept. No request, no network.

Master hand-merge (B-001, from Huntress only; csctf never had speedrun/): kept with script_pool as the worker
side of the warm pool. Changes from Huntress:
  - The speed reader is a plug-in. Huntress imported its day-specific speedrun/solvers/script_fast.py (and
    script.py's prepare_light), which the master archived. $CTF_SPEED_SCRIPT_FAST="module:function" names a
    reader with the same contract, read(member, text, qs) -> {qid: value} or None (None: not answered whole).
    Unset, there is no speed reader by design and every specimen goes to the shipped solver (exact, slower).
    Set but not loadable, FastReaderError names it: at worker boot (the worker exits before "ready") and
    at the first read in an in-process run. No silent fallback. A module the checkout defines is loaded from
    the checkout even when an installed top-level package of the same name would shadow it (SH-06: the
    checkout's tests/ is a namespace package, and any regular `tests` package on sys.path beats it). The
    worker's own namespace packages (speedrun, solvers) are pinned to the checkout the same way when it is
    imported (pin_checkout_namespaces).
  - The shipped solver is solvers/script-analysis/analyze.py read directly (Huntress resolved it through
    tools/lanes.py, which the master does not carry); a missing one raises ShippedSolverMissing.
  - Env names: CTF_SPEED_SCRIPT_FORCE_SHIPPED (was HUNTRESS_SPEED_SCRIPT_FORCE_SHIPPED).
"""
from __future__ import annotations

import contextlib
import gc
import hashlib
import zlib
import io
import os
import pickle
import struct
import time
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
for p in (str(ROOT / "tools"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import importlib  # noqa: E402
import importlib.machinery  # noqa: E402
import importlib.util  # noqa: E402

SOLVER_REL = Path("solvers") / "script-analysis" / "analyze.py"
FAST_ENV = "CTF_SPEED_SCRIPT_FAST"


class ShippedSolverMissing(FileNotFoundError):
    """The shipped script-analysis solver this worker falls back to is not in the checkout."""


class FastReaderError(ImportError):
    """$CTF_SPEED_SCRIPT_FAST names a speed reader that cannot be loaded."""


def checkout_module(mod: str):
    """(file, top-level location) of dotted module `mod` as this checkout defines it, or None when it does not.

    Looked up under ROOT, then ROOT/tools (the worker's sys.path order): <base>/a/b.py or <base>/a/b/__init__.py.
    The top-level location is <base>/a (a package, regular or namespace) or <base>/a.py (a plain module)."""
    parts = mod.split(".")
    if not all(p.isidentifier() for p in parts):
        return None
    for base in (ROOT, ROOT / "tools"):
        stem = base.joinpath(*parts)
        for f in (stem.parent / (parts[-1] + ".py"), stem / "__init__.py"):
            if f.is_file():
                top = base / parts[0]
                if not top.is_dir():
                    top = base / (parts[0] + ".py")
                return f.resolve(), top.resolve()
    return None


def _top_resolves_to(name: str, loc: Path) -> bool:
    """True when a plain import of top-level `name` would come from `loc`. Executes nothing: the module already
    in sys.modules, else what the path finder sees (a regular package anywhere on sys.path beats a namespace
    package, which is how an installed top-level `tests` shadows this checkout's tests/)."""
    have = sys.modules.get(name)
    if have is not None:
        locs = list(getattr(have, "__path__", None) or []) + [getattr(have, "__file__", None)]
    else:
        found = importlib.machinery.PathFinder.find_spec(name)
        if found is None:
            return False
        locs = list(found.submodule_search_locations or []) + [found.origin]
    return any(x and Path(x).resolve() == loc for x in locs)


# The checkout's namespace packages the worker itself imports from: speedrun.common, and solvers.common (which
# speedrun.common imports). Like tests/, neither has an __init__.py, so a regular top-level package of the same
# name installed anywhere on sys.path would win over them.
OWN_NAMESPACES = ("speedrun", "solvers")


def pin_checkout_namespaces(names=OWN_NAMESPACES):
    """Make each top-level `name` in `names` resolve to this checkout's namespace package ROOT/name.

    A name whose plain import already comes from the checkout is left alone. Otherwise, when it is not yet
    imported, a namespace module for ROOT/name is registered in sys.modules, so its submodules load from the
    checkout. When a module from elsewhere is already imported under that name, ImportError names both."""
    for name in names:
        loc = (ROOT / name).resolve()
        if not loc.is_dir() or _top_resolves_to(name, loc):
            continue
        have = sys.modules.get(name)
        if have is not None:
            raise ImportError(f"script_worker: {name} is already imported from "
                              f"{getattr(have, '__file__', None) or list(getattr(have, '__path__', None) or [])}, "
                              f"not from this checkout's {loc}")
        _register_checkout_top(name, loc)


def _register_checkout_top(name: str, loc: Path):
    """Register the checkout's top-level package folder `loc` in sys.modules as `name` (not yet imported), so
    every `name.*` import, a reader's sibling imports included, loads from the checkout. A regular package
    (loc/__init__.py) is executed from the checkout; a namespace package gets a namespace module for loc."""
    init = loc / "__init__.py"
    if init.is_file():
        return _load_checkout_file(name, init.resolve())
    spec = importlib.machinery.ModuleSpec(name, None, is_package=True)
    spec.submodule_search_locations = [str(loc)]
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    return module


def _load_checkout_file(mod: str, path: Path):
    """Module `mod` executed from the checkout's `path`, registered under its own name."""
    have = sys.modules.get(mod)
    if have is not None:
        if Path(getattr(have, "__file__", None) or "").resolve() == path:
            return have
        raise ImportError(f"{mod} is already imported from {getattr(have, '__file__', None)}, "
                          f"not from this checkout's {path}")
    search = [str(path.parent)] if path.name == "__init__.py" else None
    spec = importlib.util.spec_from_file_location(mod, path, submodule_search_locations=search)
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(mod, None)
        raise
    return module


pin_checkout_namespaces()

from speedrun import common  # noqa: E402


def import_reader_module(mod: str):
    """Module `mod`, the checkout's own when the checkout defines it.

    A plain import resolves the top-level name first, so an installed package that shares it (ecoji 0.1.1 ships a
    top-level `tests`) would hide the checkout's module, or serve its own module of the same name. When the
    checkout defines `mod` and a plain import of its top-level name would land elsewhere (or nowhere):
      - top-level name not yet imported, and a package folder: the checkout's folder is registered under that
        name (_register_checkout_top) and `mod` is then imported normally, so the reader's own imports of its
        siblings (`from . import helper`, `import tests.helper`) load from the checkout too. This is the
        worker's case: nothing imports `tests` before the reader.
      - top-level name already imported from elsewhere, or a plain top-level .py module: the checkout's file
        for `mod` alone is loaded by path under its dotted name. The imported top-level module is not
        replaced, so a sibling import inside such a reader resolves through it (the other copy, or a loud
        ModuleNotFoundError). Only an in-process caller that imported the other copy first gets this case.
    Otherwise (the checkout does not define `mod`, or the plain import comes from the checkout) this is
    importlib.import_module."""
    own = checkout_module(mod)
    if own is None:
        return importlib.import_module(mod)
    top, (path, loc) = mod.partition(".")[0], own
    if _top_resolves_to(top, loc):
        return importlib.import_module(mod)
    if top in sys.modules or not loc.is_dir():
        return _load_checkout_file(mod, path)
    _register_checkout_top(top, loc)
    return importlib.import_module(mod)


def load_fast_reader(spec: str | None):
    """The speed reader named by "module:function", or None when `spec` is empty. Raises FastReaderError.
    A module this checkout defines is loaded from the checkout even when an installed package shadows its
    top-level name (import_reader_module)."""
    spec = (spec or "").strip()
    if not spec:
        return None
    mod, sep, attr = spec.partition(":")
    if not sep or not mod or not attr:
        raise FastReaderError(f"{FAST_ENV}={spec!r} is not 'module:function'")
    try:
        fn = getattr(import_reader_module(mod), attr)
    except (ImportError, AttributeError) as e:
        raise FastReaderError(f"{FAST_ENV}={spec!r} cannot be loaded: {type(e).__name__}: {e}") from e
    if not callable(fn):
        raise FastReaderError(f"{FAST_ENV}={spec!r} is not callable")
    return fn


_UNSET = object()
FAST = _UNSET       # read(member, text, qs) -> {qid: value} | None; resolved from $CTF_SPEED_SCRIPT_FAST on first use


def fast_reader():
    """The configured speed reader (None when $CTF_SPEED_SCRIPT_FAST is unset). Resolved lazily so a reader
    module may itself import this one. Raises FastReaderError."""
    global FAST
    if FAST is _UNSET:
        FAST = load_fast_reader(os.environ.get(FAST_ENV))
    return FAST

_SHIPPED = None
_RUN = None
_NOISE = io.StringIO()


def shipped():
    global _SHIPPED, _RUN
    if _SHIPPED is None:
        path = ROOT / SOLVER_REL
        if not path.is_file():
            raise ShippedSolverMissing(f"script_worker: the shipped script-analysis solver {path} is missing")
        import run as runmod  # tools/run.py
        _RUN = runmod
        with contextlib.redirect_stdout(_NOISE), contextlib.redirect_stderr(_NOISE):
            _SHIPPED = runmod.load_solver(str(path))
    return _SHIPPED


def _shaped(aid, raw, container, member):
    _n, q = _RUN.shaped(raw, aid)
    return q


def fallback(container, member, data, items):
    """{answer_id: value} from the shipped solver for one specimen."""
    solver = shipped()
    name = container or "evidence.zip"
    qs = [_shaped(aid, raw, container, member) for aid, raw in items]
    marker = b"PK\x05\x06speed-worker"
    files = {name: marker, f"{name} -> {member}": data, member: data}
    ctx = {"set": qs[0].get("set") if qs else 0, "delivery_name": name, "delivery": marker, "partial": {}}
    _NOISE.seek(0)
    _NOISE.truncate()
    try:
        with contextlib.redirect_stdout(_NOISE), contextlib.redirect_stderr(_NOISE):
            got = solver.solve_set(qs, files, ctx) or {}
    except Exception:  # noqa: BLE001 - a specimen that raises is left open
        got = {}
    out = {}
    for q in qs:
        v = got.get(q["qid"])
        if v is None:
            continue
        s = v if isinstance(v, str) else __import__("json").dumps(v, separators=(",", ":"))
        if not s.strip() or s.startswith("??"):
            continue
        out[q["answer_id"]] = s
    return out


def fast_qs(items):
    """The speed reader's questions from raw items [(answer_id, raw question)]."""
    out = []
    for aid, raw in items:
        qid = str(raw.get("id") or aid or "")
        m = common._SET_RE.match(qid)
        if m:
            qid = m.group(2)
        fmt = raw.get("answer_format") if isinstance(raw.get("answer_format"), dict) else {}
        out.append({"answer_id": aid, "qid": qid, "text": raw.get("question") or "",
                    "accepted_values": fmt.get("accepted_values")})
    return out


def lean_qs(items):
    """The same from lean items [(answer_id, question id or None, text or None, accepted values or None)]."""
    out = []
    match = common._SET_RE.match
    for aid, qid, text, av in items:
        qid = str(qid or aid or "")
        m = match(qid)
        if m:
            qid = m.group(2)
        out.append({"answer_id": aid, "qid": qid, "text": text or "", "accepted_values": av})
    return out


def _decode(data):
    text = data.decode("utf-8", "replace")
    return text[1:] if text[:1] == "\ufeff" else text


# Test hook: extensions whose specimens skip the speed reader (the shipped solver answers them).
_FORCE = {e.strip().lower() for e in os.environ.get("CTF_SPEED_SCRIPT_FORCE_SHIPPED", "").split(",") if e.strip()}


def read_fast(member, data, qs):
    """{answer_id: value} from the speed reader, or None when it does not answer the specimen whole (or no
    speed reader is configured)."""
    fast = fast_reader()
    if fast is None:
        return None
    if _FORCE and member.rsplit(".", 1)[-1].lower() in _FORCE:
        return None
    try:
        got = fast(member, _decode(data), qs)
    except Exception:  # noqa: BLE001 - the shipped solver reads it instead
        return None
    if not isinstance(got, dict) or any(q["qid"] not in got or got[q["qid"]] is None for q in qs):
        return None     # not answered whole: the shipped solver reads it
    return {q["answer_id"]: (got[q["qid"]] if isinstance(got[q["qid"]], str) else str(got[q["qid"]])) for q in qs}


def specimen(container, member, data, items):
    """Raw items: the speed reader, else the shipped solver."""
    got = read_fast(member, data, fast_qs(items))
    return got if got is not None else fallback(container, member, data, items)


def fast_member(z, member):
    """The member's bytes. A WinZip AES member of the known password derives only the AES key (half the
    PBKDF2 blocks: the HMAC key and the 2-byte verifier are not computed); its deflate stream then checks
    the key (a wrong key inflates garbage, which raises), and anything unusual is read the full way
    (common.ZipView: verifier, other passwords)."""
    e = z.entry(member)
    if not e.aes or e.method != 8 or common._AES is None:
        return z.read(member)
    klen = common._AES_KEYLEN.get(e.aes)
    if not klen:
        return z.read(member)
    raw = z._raw(e)
    slen = klen // 2
    salt, body = raw[:slen], raw[slen + 2:len(raw) - 10]
    key = hashlib.pbkdf2_hmac("sha1", z.password, salt, 1000, klen)
    ctr = common._Counter.new(128, initial_value=1, little_endian=True)
    plain = common._AES.new(key, common._AES.MODE_CTR, counter=ctr).decrypt(body)
    try:
        d = zlib.decompressobj(-15)
        out = d.decompress(plain) + d.flush()
        if not d.eof or d.unused_data or len(out) != e.size:
            raise ValueError("not a whole deflate stream")
        return out
    except Exception:  # noqa: BLE001 - verify the full way
        return z.read(member)


_ZCACHE: dict = {}


class _Bodies:
    def __init__(self, path):
        data = path if isinstance(path, (bytes, bytearray)) else Path(path).read_bytes()
        self.outer = common.open_zip(data)
        self.inner = {}

    def get(self, container, member):
        z = self.outer
        if container is not None:
            z = self.inner.get(container)
            if z is None:
                z = self.inner[container] = common.open_zip(self.outer.read(container))
        return fast_member(z, member)


def run_lean(path, tasks):
    """Lean tasks [(container, member, lean items)]: {answer_id: value, "__need__": [task index]}."""
    b = _Bodies(path)
    out, need = {}, []
    for i, (container, member, items) in enumerate(tasks):
        try:
            body = b.get(container, member)
        except Exception:  # noqa: BLE001 - a member that does not read is left open
            continue
        got = read_fast(member, body, lean_qs(items))
        if got is None:
            need.append(i)
        else:
            out.update(got)
    if need:
        out["__need__"] = need
    return out


def run_full(path, tasks):
    """Raw tasks [(container, member, [(answer_id, raw question)])]: speed reader, else shipped solver."""
    b = _Bodies(path)
    out = {}
    for container, member, items in tasks:
        try:
            body = b.get(container, member)
        except Exception:  # noqa: BLE001 - a member that does not read is left open
            continue
        out.update(specimen(container, member, body, items))
    return out


run_job = run_full


def warm():
    """Import and exercise both paths on a saved Day 31 variant (one container), so a try meets warm code."""
    shipped()
    try:
        root = common.data_root()
        cands = sorted(root.glob("day-*/script-analysis-day-*/time_trial/attempt.json"))[-3:]
        import json
        for p in cands:
            att = json.loads(p.read_text())
            arts = att.get("artifacts") or [{"sha256": att.get("sha256")}]
            files = list((p.parent / "artifact").glob("*"))
            if not files:
                continue
            raw = files[0].read_bytes()
            z = common.open_zip(raw)
            by = {}
            for q, aid in zip(att["questions"], att.get("answer_ids") or []):
                art = q.get("artifact") or ""
                cont, _, mem = art.partition(" -> ")
                by.setdefault(mem.strip(), []).append((aid, q))
            for i, (mem, items) in enumerate(by.items()):
                if mem in z:
                    body = z.read(mem)
                    specimen(None, mem, body, items)
                    if i % 4 == 0:
                        fallback(None, mem, body, items)
    except Exception:  # noqa: BLE001 - warming is best effort
        pass


def main():
    proto_out = os.fdopen(os.dup(1), "wb", buffering=0)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    proto_in = os.fdopen(os.dup(0), "rb", buffering=0)
    fast_reader()      # a bad $CTF_SPEED_SCRIPT_FAST stops the worker here, before "ready"
    warm()

    def send(obj):
        b = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
        proto_out.write(struct.pack("<I", len(b)) + b)

    def recv_exact(n):
        buf = bytearray()
        while len(buf) < n:
            c = proto_in.read(n - len(buf))
            if not c:
                return None
            buf += c
        return bytes(buf)

    gc.collect()
    gc.freeze()        # the warm imports are never collected again
    gc.disable()       # no cyclic GC inside a job; a collection runs after each reply, between tries
    send("ready")
    while True:
        h = recv_exact(4)
        if h is None:
            return
        n = struct.unpack("<I", h)[0]
        body = recv_exact(n)
        if body is None:
            return
        job = pickle.loads(body)
        if job == "ping":
            send("pong")
            continue
        try:
            t0 = time.perf_counter()
            kind, path, tasks = job
            res = run_lean(path, tasks) if kind == "lean" else run_full(path, tasks)
            res["__t__"] = (time.perf_counter() - t0, len(tasks))
        except Exception as e:  # noqa: BLE001
            res = {"__error__": f"{type(e).__name__}: {e}"}
        send(res)
        gc.collect()


if __name__ == "__main__":
    main()
