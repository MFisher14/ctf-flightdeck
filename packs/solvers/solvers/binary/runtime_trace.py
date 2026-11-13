#!/usr/bin/env python3
"""B-242: runtime semantic adapters -- a bounded trace of a managed or bytecode artifact, run in a pinned container.

Extraction stops at structure: B-054 unpacks a .NET bundle or a Node single-executable and B-167
recovers ``.pyc`` and Java source, but what a managed crackme *computes* (the string its static
initialiser decodes, what ``check(input)`` returns, what a script prints) was left to a model. This
engine runs the artifact for a short, bounded trace and reports what it did:

  runtime   reads                                        fuel
  wasm      a core WebAssembly module                    wasmtime fuel (instructions)
  python    a ``.pyc``, on the CPython that wrote it     bytecode instructions
  lua       Lua source or bytecode (5.1-5.4, LuaJIT)     VM instructions
  jvm       a Java ``.class`` or ``.jar``                wall time
  dotnet    a CIL assembly                               wall time
  node      JavaScript, or V8 cached data (``.jsc``)     wall time

It is the one engine of the master that executes a delivered file, so three things hold:

1. **The event must allow it.** ``rules.sandboxed_execution`` is ``forbidden`` unless the player
   sets it (``ctf.eventpolicy.execution_refusal``). When it is forbidden nothing is run and no
   container is asked for: the result is ``blocked``, naming the key and the artifacts it found.
2. **Nothing runs on the host.** Each run is one fresh container of a ``ctf-runtime-*`` image
   (``docker/runtime/``), started only by ``tools/sandbox.py runtime_run``: no network, no host
   mount, read-only root, every capability dropped, CPU / memory / process / time limits. The
   artifact goes in on stdin and one trace line comes back on stdout.
3. **The image is pinned.** ``runtime_run`` refuses an image that does not carry the content hash
   of the files it is built from, and runs it by its image id. An image that is not built is
   ``blocked`` with the build command (building is a human step).

It computes behind the earlier steps and does not extract again: it reads the handout (``files/``
and the folder root), B-054's ``recon/unpack/`` (bundle assemblies, a SEA main script) and B-167's
``recon/recover/`` (the ``.pyc`` files of a PyInstaller archive). Source text in the handout is only
traced when named with ``only=<path>``.

A trace is written to ``recon/runtime/<file>-<hash>/trace.json`` and is untrusted data: it was
produced beside the artifact. A flag-format string in it is a ``candidate``, never ``solved``.
IL2CPP metadata and Dart / Flutter snapshots are named in the notes as not covered: neither is run
by a stock runtime (see docs/build-log/B-242.md).

Entry: ``solve(challenge_dir, profile, **opts) -> SolverResult``. Options (``ctf run ... --opt k=v``):
``only`` (a path under the challenge folder), ``probe`` (an extra input offered to entry points),
``seconds`` (the time budget of one run), ``fuel`` (instructions, for wasm / python / lua). Any other
option is refused (``blocked``), so a mistyped ``onyl=`` never widens a run to every artifact. The
whole call's time budget and clock are not options: ``trace_challenge`` takes them (tests use it).

When more than MAX_ARTIFACTS artifacts are found, the ones kept are chosen by rank, not by name: a
.NET entry assembly (named by a sibling ``<name>.runtimeconfig.json`` / ``<name>.deps.json``, or by
the bundle folder B-054 unpacked it into) first, framework assemblies (``System.*``,
``Microsoft.*``, ``mscorlib``, ``netstandard``, ...) last, everything else in walk order between.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ENGINE = "binary.runtime_trace"
MAX_ARTIFACTS = 12                 # artifacts traced in one call (the rest are counted)
MAX_WALK = 4000                    # files looked at in one call
MAX_SIBLINGS = 64                  # files of an artifact's folder examined as its dependencies
MAX_NATIVE_SEARCH = 64 << 20       # a native file larger than this is not searched for Dart symbols
HEAD_BYTES = 16
OVERALL_BUDGET = 600.0             # seconds for one whole solve()
MIN_RUN_SECONDS = 5                # a run is not started with less than this left of the budget
OUT = Path("recon") / "runtime"
DEFAULT_PROBES = (b"", b"AAAAAAAA")
_SKIP_TOP = {"recon", "unpacked"}  # intake's own output under the challenge folder
_UPSTREAM = (("recon/unpack", Path("recon") / "unpack"), ("recon/recover", Path("recon") / "recover"))
_IL2CPP_MAGIC = b"\xaf\x1b\xb1\xfa"
_DART_MAGICS = (b"\xf5\xf5\xdc\xdc", b"\xdc\xdc\xf5\xf5")
_DART_SYMBOL = b"_kDartIsolateSnapshot"
_NATIVE = (b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_SOURCE_EXT = (".js", ".cjs", ".lua", ".py")
OPTIONS = ("only", "probe", "fuel", "seconds")          # the solve() options; anything else is refused
# Assemblies a .NET runtime ships (a self-contained bundle carries them all): kept last, if at all.
_FRAMEWORK_PREFIXES = ("system.", "microsoft.", "runtime.", "windows.")
_FRAMEWORK_NAMES = {"system", "mscorlib", "netstandard", "windowsbase", "presentationcore",
                    "presentationframework"}
RANK_ENTRY, RANK_OTHER, RANK_FRAMEWORK = 0, 1, 2

SANDBOX_CLIENT = Path(__file__).resolve().parents[2] / "tools" / "sandbox.py"
PLANS = Path(__file__).resolve().with_name("_runtime_plans.py")
_SANDBOX = None
_PLANS = None


class Unavailable(RuntimeError):
    """A collaborator module could not be loaded (distinct from the sandbox being down)."""


def _load(path: Path, alias: str):
    try:
        spec = importlib.util.spec_from_file_location(alias, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)
    except Exception as e:                                          # noqa: BLE001 - reported, never swallowed
        sys.modules.pop(alias, None)
        raise Unavailable(f"{path.name} could not be loaded ({type(e).__name__}: {e})") from e
    return module


def load_sandbox():
    """The ``tools/sandbox.py`` module (loaded once, by path): the only way a container is started."""
    global _SANDBOX
    if _SANDBOX is None:
        _SANDBOX = _load(SANDBOX_CLIENT, "ctf_runtime_trace_sandbox")
    return _SANDBOX


def load_plans():
    """The sibling ``_runtime_plans`` helper (classify, build_plan, request_members, parse_trace)."""
    global _PLANS
    if _PLANS is None:
        _PLANS = _load(PLANS, "ctf_runtime_trace_plans")
    return _PLANS


# --------------------------------------------------------------------------------------------- scan
@dataclass
class Found:
    path: Path
    rel: str
    data: bytes
    target: object                 # _runtime_plans.Target
    origin: str                    # handout | recon/unpack | recon/recover | only


@dataclass
class Scan:
    found: list = field(default_factory=list)
    skipped: list = field(default_factory=list)       # "<rel>: <why>" -- unreadable or over the size cap
    unsupported: list = field(default_factory=list)   # recognised, but no image reads that version
    uncovered: list = field(default_factory=list)     # IL2CPP / Dart: named, no adapter exists
    duplicates: list = field(default_factory=list)
    overflow: int = 0                                 # artifacts over MAX_ARTIFACTS
    dropped: list = field(default_factory=list)       # the rel path of each of them
    walk_cut: bool = False                            # MAX_WALK files were looked at; the rest were not


def _plausible(head: bytes, name: str, source: bool) -> bool:
    """Whether a file's first bytes (or its name) can be something this engine reads or names."""
    low = name.lower()
    return (head[:4] in (b"\x00asm", b"\xca\xfe\xba\xbe", _IL2CPP_MAGIC) or head[:4] in _DART_MAGICS
            or head[:2] in (b"PK", b"MZ") or head[2:4] == b"\r\n" or head[:3] == b"\x1bLJ"
            or head[:4] == b"\x1bLua" or head[:4] in _NATIVE or low.endswith(".jsc")
            or (source and (low.endswith(_SOURCE_EXT) or low == "main")))


def _uncovered(data: bytes) -> str | None:
    """A sentence naming an artifact no adapter runs (IL2CPP metadata, a Dart snapshot), else None."""
    if data[:4] == _IL2CPP_MAGIC and len(data) >= 8:
        version = int.from_bytes(data[4:8], "little", signed=True)
        return (f"Unity IL2CPP global-metadata version {version}: no adapter maps its methods to the native "
                "code (the metadata readers are toolkits.il2cpp and binary.redepth_il2cpp_modern)")
    if data[:4] in _DART_MAGICS:
        tag = data[20:52].decode("ascii", "replace") if len(data) >= 52 else "?"
        return (f"Dart snapshot (version hash {tag}): no adapter runs it, it needs the Dart VM of exactly "
                "that build (the static reader is binary.redepth_dart_snapshot)")
    if data[:4] in _NATIVE and _DART_SYMBOL in data:
        return ("Flutter / Dart AOT library (it exports _kDartIsolateSnapshot*): no adapter runs it "
                "(the static reader is binary.redepth_dart_snapshot)")
    return None


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _stem(name: str) -> str:
    low = name.lower()
    for ext in (".dll", ".exe"):
        if low.endswith(ext):
            return low[:-len(ext)]
    return low


def rank(path: Path, target, challenge_dir: Path) -> int:
    """Which artifacts are kept first when there are more than MAX_ARTIFACTS: RANK_ENTRY for a .NET
    entry assembly (a sibling ``<stem>.runtimeconfig.json`` or ``<stem>.deps.json`` names it, or it
    has the name of the ``recon/unpack/<host>/`` folder B-054 unpacked it into), RANK_FRAMEWORK for
    an assembly the .NET runtime itself ships, RANK_OTHER for everything else."""
    if target.runtime != "dotnet":
        return RANK_OTHER
    stem = _stem(path.name)
    if stem in _FRAMEWORK_NAMES or stem.startswith(_FRAMEWORK_PREFIXES):
        return RANK_FRAMEWORK
    for suffix in (".runtimeconfig.json", ".deps.json"):
        sib = path.parent / (path.name[:len(stem)] + suffix)
        if not sib.is_symlink() and sib.is_file():
            return RANK_ENTRY
    parts = path.relative_to(challenge_dir).parts
    if len(parts) >= 4 and parts[:2] == ("recon", "unpack") and _stem(parts[2]) == stem:
        return RANK_ENTRY
    return RANK_OTHER


def scan(challenge_dir: Path, only: str | None = None) -> Scan:
    """The artifacts this engine traces: the handout (``files/``, then the folder root without
    intake's ``recon/`` and ``unpacked/``), then ``recon/unpack`` and ``recon/recover``, walked in
    name order. Only a file whose first bytes are plausible is read; identical bodies are taken once.
    At most MAX_ARTIFACTS are kept, chosen by ``rank`` and then walk order, and they are given back
    in that order, so an entry assembly is traced first and a framework assembly last. With
    ``only``, that one file (inside the folder) and nothing else."""
    plans = load_plans()
    out = Scan()
    seen_paths: set[Path] = set()
    seen_bodies: set[str] = set()
    kept: list[tuple[int, int, Found]] = []           # (rank, walk order, artifact)
    looked = 0

    def take(f: Path, origin: str, source: bool) -> None:
        nonlocal looked
        rel = str(f.relative_to(challenge_dir))
        try:
            real = f.resolve()
            if real in seen_paths:
                return
            seen_paths.add(real)
            size = f.stat().st_size
            with open(f, "rb") as fh:
                head = fh.read(HEAD_BYTES)
        except OSError as e:
            out.skipped.append(f"{rel}: could not be read ({type(e).__name__})")
            return
        looked += 1
        if not _plausible(head, f.name, source):
            if origin == "only":
                out.skipped.append(f"{rel}: no runtime adapter reads it")
            return
        native = head[:4] in _NATIVE
        if size > (MAX_NATIVE_SEARCH if native else plans.MAX_ARTIFACT_BYTES):
            if not native or origin == "only":
                out.skipped.append(f"{rel}: {size} bytes is over the {plans.MAX_ARTIFACT_BYTES} byte cap")
            return
        try:
            data = f.read_bytes()
        except OSError as e:
            out.skipped.append(f"{rel}: could not be read ({type(e).__name__})")
            return
        why = _uncovered(data)
        if why:
            out.uncovered.append(f"{rel}: {why}")
            return
        name = f.name + ".js" if source and f.name.lower() == "main" else f.name
        target = plans.classify(data, name, source=source)
        if target is None:
            if origin == "only":
                out.skipped.append(f"{rel}: no runtime adapter reads it")
            return
        if not target.variants:
            out.unsupported.append(f"{rel}: {target.note}")
            return
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen_bodies:
            out.duplicates.append(rel)
            return
        seen_bodies.add(digest)
        kept.append((rank(f, target, challenge_dir), len(seen_bodies), Found(f, rel, data, target, origin)))
        if len(kept) > MAX_ARTIFACTS:              # drop the worst: the highest rank, the latest in the walk
            worst = max(kept, key=lambda k: (k[0], k[1]))
            kept.remove(worst)
            out.overflow += 1
            out.dropped.append(worst[2].rel)

    def done() -> Scan:
        out.found = [k[2] for k in sorted(kept, key=lambda k: (k[0], k[1]))]
        return out

    if only is not None:
        base = challenge_dir.resolve()
        f = challenge_dir / str(only)
        if f.is_symlink() or not f.is_file() or not _inside(f.resolve(), base):
            out.skipped.append(f"{only}: not a regular file inside the challenge folder")
            return out
        take(f, "only", True)
        return done()

    roots = [("handout", challenge_dir / "files", False), ("handout", challenge_dir, False)]
    roots += [(label, challenge_dir / sub, label == "recon/unpack") for label, sub in _UPSTREAM]
    for origin, root, source in roots:
        for dirpath, dirnames, filenames in os.walk(root):      # a root that is not there yields nothing
            here = Path(dirpath)
            dirnames[:] = sorted(d for d in dirnames
                                 if not (here == challenge_dir and d in _SKIP_TOP)
                                 and not (here / d).is_symlink())
            for n in sorted(filenames):
                f = here / n
                if f.is_symlink() or not f.is_file():
                    continue
                if looked >= MAX_WALK:
                    out.walk_cut = True
                    return done()
                take(f, origin, source)
    return done()


def dependencies(found: Found, plans) -> list[bytes]:
    """The other files of the artifact's own folder that the same runtime reads (a jar's sibling
    jars and classes, an assembly's sibling assemblies), as bytes, in name order. Only the JVM and
    .NET resolve references; at most MAX_SIBLINGS files are examined and the request caps hold."""
    if found.target.runtime not in ("jvm", "dotnet"):
        return []
    out: list[bytes] = []
    total = len(found.data)
    try:
        siblings = sorted(p for p in found.path.parent.iterdir())[:MAX_SIBLINGS]
    except OSError:
        return []
    for p in siblings:
        if p == found.path or p.is_symlink() or not p.is_file() or len(out) >= plans.MAX_DEPS:
            continue
        try:
            if p.stat().st_size > plans.MAX_ARTIFACT_BYTES:
                continue
            body = p.read_bytes()
        except OSError:
            continue
        t = plans.classify(body, p.name)
        if t is None or t.runtime != found.target.runtime or total + len(body) > plans.MAX_REQUEST_BYTES:
            continue
        total += len(body)
        out.append(body)
    return out


# -------------------------------------------------------------------------------------------- trace
@dataclass
class Outcome:
    """One artifact's run. ``state`` is the trace's own status (ok | partial | error) when a trace
    came back, ``failed`` when a container ran and gave no valid trace, ``blocked`` when no container
    could run (image not built, daemon down, stale image)."""
    state: str
    note: str = ""
    trace: object = None
    plan: object = None
    image: str = ""
    exit_code: int | None = None


def _first_line(b: bytes) -> str:
    lines = b.decode("utf-8", "replace").strip().splitlines()
    return "".join(c if c.isprintable() else "?" for c in lines[0])[:200] if lines else ""


def trace_artifact(found: Found, *, probes, fuel, seconds, images_by_name, content_hash) -> Outcome:
    """Run ``found`` in its runtime image and give the Outcome. The image variants are tried in order
    until one loads the artifact (V8 cached data is tried on each Node line)."""
    plans, sandbox = load_plans(), load_sandbox()
    target = found.target
    members = plans.request_members(found.data, dependencies(found, plans))
    downs, fails, rejected = [], [], None
    for variant in target.variants:
        plan = plans.build_plan(target.runtime, variant, seconds=seconds, probes=probes,
                                fuel=fuel if plans.FUEL_KIND[target.runtime] == "instructions" else None)
        image = images_by_name.get(plan.image)
        if image is None:
            downs.append(f"tools/images.toml lists no image {plan.image!r}")
            continue
        hint = f"python -m ctf toolchain build --apply --only {image.name}"
        try:
            want = content_hash(image)
        except ValueError as e:                # ImagesError: the image's pins cannot be resolved
            downs.append(f"{image.tag}: its content hash cannot be computed ({e})")
            continue
        try:
            res = sandbox.runtime_run(image.tag, want, plan.argv, members, plan.container_seconds,
                                      memory=plan.memory, cpus=plan.cpus, pids=plan.pids, build_hint=hint)
        except sandbox.SandboxDown as e:
            downs.append(str(e))
            continue
        try:
            trace = plans.parse_trace(res.stdout, target.runtime)
        except plans.TraceError as e:
            stopped = f", stopped at the {plan.container_seconds} s limit" if res.code == 124 else ""
            err = _first_line(res.stderr)
            fails.append(f"{image.tag}: {e} (exit {res.code}{stopped}{'; ' + err if err else ''})")
            continue
        outcome = Outcome(trace.status, trace=trace, plan=plan, image=image.tag, exit_code=res.code)
        if trace.status == "error":
            outcome.note = f"{image.tag}: " + ("; ".join(trace.errors()[:3]) or "the runtime did not load it")
            if rejected is not None:
                outcome.note = f"{rejected.note}; {outcome.note}"
            rejected = outcome
            continue                 # another variant may read it
        if trace.status == "partial":
            parts = trace.errors()[:3] + list(trace.notes[:2])
            if trace.fuel_exhausted:
                parts.insert(0, f"out of {trace.fuel_kind} fuel ({trace.fuel_limit})")
            if trace.truncated:
                parts.append("the trace was cut at its size caps")
            outcome.note = "; ".join(parts) or "incomplete"
        return outcome
    if rejected is not None:
        if fails or downs:
            rejected.note += "; other images: " + "; ".join(fails + downs)
        return rejected
    if fails:
        return Outcome("failed", note="; ".join(fails + downs))
    return Outcome("blocked", note="; ".join(downs))


def _safe(name: str) -> str:
    clean = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120]
    return clean if clean.strip(".") else "file"


def _folder(rel: str) -> str:
    """The output folder of one artifact: its flattened path plus a short hash of the exact path."""
    flat = _safe(rel.replace("/", "__").replace("\\", "__"))
    return f"{flat}-{hashlib.sha256(rel.encode('utf-8', 'surrogateescape')).hexdigest()[:8]}"


def _describe(found: Found) -> str:
    t = found.target
    return f"{found.rel} ({t.runtime} {t.kind})"


# -------------------------------------------------------------------------------------------- solve
def solve(challenge_dir, profile, **opts):
    """Trace every managed or bytecode artifact of the challenge in its pinned runtime container.

    The options are OPTIONS (``only``, ``probe``, ``fuel``, ``seconds``): any other is ``blocked``
    before anything is looked at. Otherwise it is ``trace_challenge`` with the default time budget."""
    from ctf.result import SolverResult

    unknown = sorted(k for k in opts if k not in OPTIONS)
    if unknown:
        return SolverResult(status="blocked", engine=ENGINE,
                            notes=f"not run: unknown option {', '.join(repr(k) for k in unknown)} "
                                  f"(the options are {', '.join(OPTIONS)})")
    return trace_challenge(challenge_dir, profile, **opts)


def trace_challenge(challenge_dir, profile, *, only=None, probe=None, fuel=None, seconds=None,
                    budget: float = OVERALL_BUDGET, clock=time.monotonic):
    """``solve`` with the whole call's time ``budget`` (seconds) and ``clock`` given.

    ``blocked`` when the event forbids sandboxed execution (nothing is run, no container is asked
    for), when an option is out of bounds, or when no container could run (notes name the image and
    the build command); ``candidate`` when a trace holds a string in the event flag format;
    ``none`` when there is nothing to trace, or everything traced to completion with no flag;
    ``unsure`` otherwise: a partial trace (fuel or time ran out, a call failed), an artifact the
    runtime did not load, or a file left out, each named in the notes."""
    from ctf import eventpolicy, flagfmt
    from ctf.result import Evidence, SolverResult
    from ctf.toolchain import images

    challenge_dir = Path(challenge_dir)
    plans = load_plans()
    found_scan = scan(challenge_dir, None if only is None else str(only))
    todo = found_scan.found

    left_out = []
    if found_scan.skipped:
        left_out.append("left out: " + "; ".join(found_scan.skipped))
    if found_scan.unsupported:
        left_out.append("no image for: " + "; ".join(found_scan.unsupported))
    if found_scan.uncovered:
        left_out.append("no runtime adapter for: " + "; ".join(found_scan.uncovered))
    if found_scan.overflow:
        names = ", ".join(found_scan.dropped[:10]) + (", ..." if len(found_scan.dropped) > 10 else "")
        left_out.append(f"{found_scan.overflow} more artifact(s) not traced (over MAX_ARTIFACTS={MAX_ARTIFACTS}): "
                        f"{names}")
    if found_scan.walk_cut:
        left_out.append(f"the walk stopped after {MAX_WALK} files: later files were not looked at")
    if found_scan.duplicates:
        left_out.append("same bytes as an artifact already taken: " + ", ".join(found_scan.duplicates))
    incomplete_scan = bool(found_scan.skipped or found_scan.unsupported or found_scan.uncovered
                           or found_scan.overflow or found_scan.walk_cut)

    if not todo:
        if incomplete_scan:
            return SolverResult(status="blocked", engine=ENGINE, notes="nothing was traced. " + ". ".join(left_out))
        return SolverResult(status="none", engine=ENGINE,
                            notes="no WebAssembly module, .pyc, Lua bytecode, Java class or jar, CIL assembly or "
                                  "V8 cached data in the handout, recon/unpack or recon/recover"
                                  + (". " + ". ".join(left_out) if left_out else ""))

    listing = ", ".join(_describe(f) for f in todo)
    refusal = eventpolicy.execution_refusal(profile)
    if refusal:
        return SolverResult(status="blocked", engine=ENGINE,
                            notes=f"not run: {refusal}. Found: {listing}"
                                  + (". " + ". ".join(left_out) if left_out else ""))

    probes = list(DEFAULT_PROBES)
    prefixes = tuple(getattr(profile.flag, "prefixes", ()) or ())
    if prefixes:
        probes.append(f"{prefixes[0]}{{probe}}".encode("utf-8"))
    if probe is not None:
        probes.append(str(probe).encode("utf-8"))
    try:
        if seconds is not None and (isinstance(seconds, bool) or not isinstance(seconds, int)):
            raise plans.PlanError(f"seconds must be a whole number, got {seconds!r}")
        if fuel is not None and (isinstance(fuel, bool) or not isinstance(fuel, int)):
            raise plans.PlanError(f"fuel must be a whole number, got {fuel!r}")
        checked = set()
        for f in todo:                         # the options must hold for every runtime that will be used
            runtime = f.target.runtime
            if runtime not in checked:
                checked.add(runtime)
                plans.build_plan(runtime, f.target.variants[0], probes=probes,
                                 seconds=plans.DEFAULT_SECONDS if seconds is None else seconds,
                                 fuel=fuel if plans.FUEL_KIND[runtime] == "instructions" else None)
    except plans.PlanError as e:
        return SolverResult(status="blocked", engine=ENGINE, notes=f"not run: bad option: {e}. Found: {listing}")

    try:
        by_name = {im.name: im for im in images.load()}
    except images.ImagesError as e:
        return SolverResult(status="blocked", engine=ENGINE,
                            notes=f"not run: the image manifest is unusable ({e}). Found: {listing}")

    ff = flagfmt.for_profile(profile)
    deadline = clock() + budget
    want_seconds = plans.DEFAULT_SECONDS if seconds is None else seconds
    evidence, flags = [], []
    traced, partial, errored, failed, blocked, unreached = [], [], [], [], [], []
    for f in todo:
        room = int(deadline - clock()) - plans.GRACE_SECONDS
        if room < MIN_RUN_SECONDS:
            unreached.append(f.rel)
            continue
        out = trace_artifact(f, probes=probes, fuel=fuel, seconds=min(want_seconds, room),
                             images_by_name=by_name, content_hash=images.content_hash)
        desc = _describe(f)
        if out.state == "blocked":
            blocked.append(f"{desc}: {out.note}")
            continue
        if out.state == "failed":
            failed.append(f"{desc}: {out.note}")
            continue
        dest = challenge_dir / OUT / _folder(f.rel) / "trace.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps({
            "artifact": f.rel, "origin": f.origin, "sha256": hashlib.sha256(f.data).hexdigest(),
            "size": len(f.data), "kind": f.target.kind, "image": out.image, "exit_code": out.exit_code,
            "plan": out.plan.to_dict(), "trace": out.trace.to_dict(),
        }, indent=1, sort_keys=True), encoding="utf-8")
        rel_out = str(dest.relative_to(challenge_dir))
        t = out.trace
        evidence.append(Evidence(kind="trace",
                                 detail=f"{t.runtime} {t.runtime_version} traced {f.rel} in {out.image}: "
                                        f"{len(t.entries)} entry point(s), {len(t.events)} event(s), "
                                        f"{len(t.strings)} string(s) observed, status {t.status}",
                                 path=rel_out))
        hits = [fl for fl in ff.find_flags("\n".join(t.texts())) if fl not in flags]
        if hits:
            flags.extend(hits)
            evidence.append(Evidence(kind="trace", detail=f"flag-format string observed at run time in {f.rel}",
                                     path=rel_out))
        if out.state == "ok":
            traced.append(desc)
        elif out.state == "partial":
            partial.append(f"{desc}: {out.note}")
        else:
            errored.append(f"{desc}: {out.note}")

    notes = []
    if traced:
        notes.append("traced " + ", ".join(traced) + f" to {OUT}/")
    if partial:
        notes.append("traced in part: " + "; ".join(partial))
    if errored:
        notes.append("the runtime did not load: " + "; ".join(errored))
    if failed:
        notes.append("no trace came back for: " + "; ".join(failed))
    if blocked:
        notes.append("no container could run for: " + "; ".join(blocked))
    if unreached:
        notes.append(f"not traced, the {budget:g} s time budget was spent: " + ", ".join(unreached))
    notes += left_out
    note = ". ".join(notes)
    incomplete = bool(partial or errored or failed or blocked or unreached or incomplete_scan)

    if flags:
        return SolverResult(status="candidate", flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE,
                            notes="flag-format string(s) observed while tracing (dynamic, unverified: the trace is "
                                  "produced beside the artifact). " + note)
    if traced and not incomplete:
        return SolverResult(status="none", evidence=tuple(evidence), engine=ENGINE, notes=note)
    if traced or partial or errored:
        return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE, notes=note)
    if blocked and not failed:
        return SolverResult(status="blocked", evidence=tuple(evidence), engine=ENGINE,
                            notes="nothing was traced. " + note)
    return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE, notes="nothing was traced. " + note)
