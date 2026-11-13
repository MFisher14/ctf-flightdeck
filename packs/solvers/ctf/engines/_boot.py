"""Engine bootstrap, started as `<python> -I ctf/engines/_boot.py --repo <root> [options] <target> [args]`
by `python -m ctf run` and tools/ctfpy. Not imported by anything; not a CLI for people.

Options (before the target):
  --repo DIR          the checkout to run from (required; the boot does not guess it)
  --via NAME          recorded in the ledger (ctf-run, ctfpy)
  --no-ledger         do not record the run
  --challenge-id ID   recorded with the run
Targets:
  --engine NAME       a manifested engine (see ctf/engines/runner.py for how each entry kind runs)
  -m MODULE           run a module as __main__, like `python -m`
  -c CODE             run code, like `python -c`
  --info              print the interpreter, repo, sys.path and workdir this wrapper uses
  SCRIPT              a .py file, like `python SCRIPT` (recorded when it is a manifested engine)
  NAME                an engine name, when no such file exists
  (none)              an interactive console with the engine sys.path
"""
from __future__ import annotations

import sys


def _setup(repo: str) -> None:
    from pathlib import Path
    root = Path(repo).resolve()
    if not (root / "ctf" / "__init__.py").is_file():
        print(f"ctfpy: --repo {repo} is not a ctf-tools checkout", file=sys.stderr)
        raise SystemExit(2)
    sys.path.insert(0, str(root))
    from ctf.engines import layout
    for p in reversed(layout.sys_path(root)):
        if p in sys.path:
            sys.path.remove(p)
        sys.path.insert(0, p)
    import os
    from ctf.engines import runner
    os.environ.update(runner.child_env())


def _exit_code(e: SystemExit) -> int:
    if e.code is None:
        return 0
    if isinstance(e.code, int):
        return e.code
    print(e.code, file=sys.stderr)
    return 1


def _call(fn) -> int:
    import traceback
    try:
        r = fn()
        return r if isinstance(r, int) else 0
    except SystemExit as e:
        return _exit_code(e)
    except KeyboardInterrupt:
        return 130
    except BaseException:
        traceback.print_exc()
        return 1


def _run_script(path: str, args: list[str]) -> int:
    import os
    import runpy
    sys.argv = [path, *args]
    sys.path.insert(0, os.path.dirname(os.path.abspath(path)))   # what plain `python script.py` does
    return _call(lambda: runpy.run_path(path, run_name="__main__") and 0)


class _Tee:
    def __init__(self, real):
        self.real, self.parts = real, []

    def write(self, s):
        self.parts.append(s)
        return self.real.write(s)

    def flush(self):
        self.real.flush()

    def __getattr__(self, name):
        return getattr(self.real, name)


def _parse_opts(args: list[str]):
    import json
    if not args or args[0].startswith("-"):
        raise SystemExit("usage: ctf run <engine> <challenge_dir> [--opt key=value]... [--event slug]")
    challenge_dir, rest, opts, slug = args[0], args[1:], {}, None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--opt", "--event") and i + 1 < len(rest):
            if a == "--event":
                slug = rest[i + 1]
            else:
                k, sep, v = rest[i + 1].partition("=")
                if not sep or not k.isidentifier():
                    raise SystemExit(f"--opt {rest[i + 1]!r}: expected key=value")
                try:
                    opts[k] = json.loads(v)        # numbers, true/false, lists; else the plain string
                except ValueError:
                    opts[k] = v
            i += 2
            continue
        raise SystemExit(f"unexpected argument {a!r} (contract engines take <challenge_dir> [--opt k=v]...)")
    return challenge_dir, opts, slug


def _load_function(m, root):
    import importlib
    import importlib.util
    from ctf.engines import layout
    target = m.entry.target_file(root)
    if layout.flat_owner(target.stem, root) == target:
        mod = importlib.import_module(target.stem)        # the same module object flat importers get
    else:
        spec = importlib.util.spec_from_file_location(f"_ctf_engine_{m.id.replace('.', '_')}", target)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
    return getattr(mod, m.entry.function)


def _run_engine(m, args: list[str], root) -> tuple[int, str | None]:
    """(exit code, SolverResult status or None)."""
    import subprocess
    from pathlib import Path
    from ctf.result import SolverResult
    e = m.entry
    if e.kind == "function":
        if m.has("library"):
            print(f"ctf run: {m.id} is import-only (library): {m.entry_raw} is not an engine entry. "
                  f"Import it from Python instead, e.g. tools/ctfpy -c 'import {m.basename}'", file=sys.stderr)
            return 2, None
        try:
            challenge_dir, opts, slug = _parse_opts(args)
        except SystemExit as ex:
            return _exit_code(ex), None
        from ctf import event
        holder = {}

        def call():
            profile = event.load(slug) if slug else event.current()
            fn = _load_function(m, root)
            res = fn(Path(challenge_dir), profile, **opts)
            if not isinstance(res, SolverResult):
                print(f"ctf run: {m.id} returned {type(res).__name__}, not a SolverResult", file=sys.stderr)
                return 2
            holder["status"] = res.status
            print(res.to_json())
            return 0
        return _call(call), holder.get("status")
    if e.is_python_cli:
        script = str(root / e.argv[1])
        argv = [*e.argv[2:], *args]
        if m.has("legacy-output"):
            return _run_script(script, argv), None
        tee = _Tee(sys.stdout)
        sys.stdout = tee
        try:
            code = _run_script(script, argv)
        finally:
            sys.stdout = tee.real
        lines = [ln for ln in "".join(tee.parts).splitlines() if ln.strip()]
        try:
            res = SolverResult.from_json(lines[-1]) if lines else None
        except (ValueError, TypeError, KeyError) as ex:
            print(f"ctf run: {m.id} did not end with a SolverResult JSON line ({ex})", file=sys.stderr)
            res = None
        return code, (None if res is None else res.status)
    return subprocess.call([*e.argv, *args]), None


def main(argv: list[str]) -> int:
    opts = {"via": "ctfpy", "ledger": True, "challenge_id": None, "repo": None}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--repo" and i + 1 < len(argv):
            opts["repo"] = argv[i + 1]
        elif a == "--via" and i + 1 < len(argv):
            opts["via"] = argv[i + 1]
        elif a == "--challenge-id" and i + 1 < len(argv):
            opts["challenge_id"] = argv[i + 1]
        elif a == "--no-ledger":
            opts["ledger"] = False
            i += 1
            continue
        else:
            break
        i += 2
    if not opts["repo"]:
        print("ctfpy: internal error: --repo not given", file=sys.stderr)
        return 2
    _setup(opts["repo"])
    rest = argv[i:]

    import time
    from pathlib import Path
    from ctf.engines import manifest as _manifest, runner
    root = Path(opts["repo"]).resolve()

    def recorded(m, fn):
        t0 = time.monotonic()
        code, status = fn()
        if runner.recording_enabled(not opts["ledger"]):
            runner.record_run(m.id, exit_code=code, seconds=time.monotonic() - t0, via=opts["via"],
                              status=status, challenge_id=opts["challenge_id"])
        return code

    if not rest:
        import code as _code
        _code.interact(banner=f"ctfpy {sys.version.split()[0]} (engine sys.path from {root})",
                       local={"__name__": "__main__"})
        return 0
    head, args = rest[0], rest[1:]
    if head == "--info":
        print(f"python   {sys.executable}")
        print(f"repo     {root}")
        from ctf import paths
        from ctf.event import EventError
        try:
            wd = str(paths.workdir())
        except EventError:
            wd = "(none: set CTF_WORKDIR or CTF_EVENT)"
        print(f"workdir  {wd}")
        print("sys.path " + "\n         ".join(p for p in sys.path if p))
        return 0
    if head == "-c":
        if not args:
            print("ctfpy: -c needs code", file=sys.stderr)
            return 2
        sys.argv = ["-c", *args[1:]]
        return _call(lambda: exec(compile(args[0], "<string>", "exec"), {"__name__": "__main__"}))
    if head == "-m":
        if not args:
            print("ctfpy: -m needs a module", file=sys.stderr)
            return 2
        import runpy
        sys.argv = [args[0], *args[1:]]
        return _call(lambda: runpy.run_module(args[0], run_name="__main__", alter_sys=True) and 0)
    try:
        if head == "--engine":
            if not args:
                print("ctfpy: --engine needs a name", file=sys.stderr)
                return 2
            m = runner.resolve(args[0], root=root)
            return recorded(m, lambda: _run_engine(m, args[1:], root))
        p = Path(head)
        if p.is_file():
            m = None
            if p.suffix == ".py" and any(str(p.resolve()).startswith(str(root / d) + "/")
                                         for d in _manifest.ENGINE_ROOTS):
                side = _manifest.sidecar_for(p.resolve())
                m = _manifest.load(side) if side.exists() else None
            if m is None:
                return _run_script(head, args)
            return recorded(m, lambda: (_run_script(head, args), None))
        m = runner.resolve(head, root=root)
        return recorded(m, lambda: _run_engine(m, args, root))
    except (runner.EngineError, _manifest.ManifestError) as e:
        print(f"ctfpy: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
