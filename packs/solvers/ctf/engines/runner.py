"""One way to run an engine (B-187): resolve it by name, run it with the right interpreter, sys.path
and environment, and record the run in the event ledger (B-186's real-use metric).

    python -m ctf run <engine> [args...]       # engine = id, name, basename or path
    tools/ctfpy <engine|script.py|-m mod|-c code> [args...]

Both start `<python> -I ctf/engines/_boot.py --repo <root> ...`: isolated mode (no PYTHONPATH, no
user site, no script-dir injection), then the boot puts tools/, every solvers/<lane>/ and the repo
root on sys.path in the same precedence as the test suite, so the carried flat imports keep working
without an editable install or an import rewrite.

How an engine runs depends on its manifest entry:

  cli:python <script>   run the script as __main__ with the given args (what `python <script>` did).
                        Without the `legacy-output` tag the script must print one SolverResult JSON
                        line; it is parsed and its status recorded.
  cli:<tool> ...        the external command, args appended.
  module:function       a contract engine: `ctf run <id> <challenge_dir> [--opt k=v]... [--event slug]`
                        calls function(challenge_dir, profile, **opts) and prints the SolverResult JSON.
                        A `library` engine (import-only carried module) is refused, not guessed at.

Ledger: every run appends `engine.run` {engine, via, exit_code, seconds, status?, challenge_id?} to
`<workdir>/ledger.jsonl`. With no resolvable workdir the run still happens and stderr says it was not
recorded and why. `--no-ledger` or CTF_ENGINE_LEDGER=0 turns recording off on purpose.
"""
from __future__ import annotations

import difflib
import os
import sys
from pathlib import Path

from .. import paths
from . import manifest as _manifest

LEDGER_EVENT = "engine.run"


class EngineError(RuntimeError):
    """An engine name does not resolve, is ambiguous, or cannot be run."""


def resolve(name: str, *, root: Path | None = None,
            manifests: list[_manifest.Manifest] | None = None) -> _manifest.Manifest:
    """id ("toolkits.network"), name after the lane ("network"), basename ("network.py") or a path
    to the module or its sidecar. Ambiguity and misses raise EngineError naming the candidates."""
    root = paths.repo_root() if root is None else Path(root)
    ms = _manifest.discover(root) if manifests is None else manifests
    by_id = {m.id: m for m in ms}
    if name in by_id:
        return by_id[name]
    p = Path(name)
    if p.suffix in (".py", ".toml") or "/" in name:
        cand = (p if p.is_absolute() else Path.cwd() / p).resolve()
        if not cand.exists():
            cand = (root / p).resolve()
        hits = [m for m in ms if cand in (m.module_path.resolve(), m.path.resolve())]
        if hits:
            return hits[0]
        if "/" in name:
            raise EngineError(f"{name}: no engine manifest for that path")
    stem = p.name[:-3] if p.name.endswith(".py") else p.name
    hits = [m for m in ms if m.name == stem or m.basename == stem]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise EngineError(f"{name!r} is ambiguous: " + ", ".join(m.id for m in hits) + " (use the id)")
    close = difflib.get_close_matches(name, list(by_id) + [m.name for m in ms], n=5, cutoff=0.6)
    raise EngineError(f"no engine {name!r}" + (f"; did you mean: {', '.join(close)}" if close else
                                               "; list them with `python -m ctf engines list`"))


def boot_script(root: Path | None = None) -> Path:
    root = paths.repo_root() if root is None else Path(root)
    return root / "ctf" / "engines" / "_boot.py"


def command(engine_id: str, args: list[str], *, python: str | None = None, root: Path | None = None,
            via: str = "ctf-run", record: bool = True, challenge_id: str | None = None) -> list[str]:
    root = paths.repo_root() if root is None else Path(root)
    cmd = [python or sys.executable, "-I", str(boot_script(root)), "--repo", str(root), "--via", via]
    if not record:
        cmd.append("--no-ledger")
    if challenge_id:
        cmd += ["--challenge-id", str(challenge_id)]
    return cmd + ["--engine", engine_id, *args]


def run(name: str, args: list[str], *, root: Path | None = None, record: bool = True,
        challenge_id: str | None = None) -> int:
    import subprocess
    m = resolve(name, root=root)
    return subprocess.call(command(m.id, list(args), root=root, record=record, challenge_id=challenge_id))


def child_env(environ: dict | None = None) -> dict:
    """The environment an engine runs with: the caller's, with CTF_WORKDIR set to ctf.paths.workdir()
    ($CTF_WORKDIR when set, else the current event's) so carried engines that read it directly find it."""
    from ..event import EventError
    env = dict(os.environ if environ is None else environ)
    try:
        env["CTF_WORKDIR"] = str(paths.workdir())
    except EventError:     # no event resolvable: leave it as it was; engines that need it say so
        pass
    return env


def recording_enabled(no_ledger: bool = False) -> bool:
    from .. import env as _env
    return not no_ledger and _env.get_bool("CTF_ENGINE_LEDGER", True)


def record_run(engine_id: str, *, exit_code: int, seconds: float, via: str, status: str | None = None,
               challenge_id: str | None = None, workdir: Path | None = None) -> dict | None:
    """Append engine.run to the ledger. Returns the record, or None (with a stderr notice naming the
    reason) when no workdir resolves."""
    from .. import ledger
    from ..event import EventError
    fields = {"engine": engine_id, "via": via, "exit_code": int(exit_code), "seconds": round(seconds, 3)}
    if status is not None:
        fields["status"] = status
    if challenge_id:
        fields["challenge_id"] = str(challenge_id)
    try:
        return ledger.append(LEDGER_EVENT, workdir=workdir, **fields)
    except EventError as e:
        print(f"ctf: engine run not recorded in the ledger: {e} "
              "(set CTF_WORKDIR or CTF_EVENT, or pass --no-ledger)", file=sys.stderr)
        return None
